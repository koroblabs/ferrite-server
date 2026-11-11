//! The database connection, on a thread of its own.
//!
//! SQLite calls block, so the connection lives on a dedicated thread and async
//! code hands it closures over a channel; each answer comes back on a oneshot.
//! Calls run one at a time, in the order they were made, which is the single
//! connection the storage layer was written around.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::mpsc;
use std::thread;

use ferrite_core::error::{FeriteError, Result};
use tokio::sync::oneshot;

type Job = Box<dyn FnOnce(&mut rusqlite::Connection) + Send>;

/// A handle to the connection thread. Clones share the one connection; the
/// thread closes it once the last handle is dropped.
#[derive(Clone, Debug)]
pub(super) struct Connection {
    jobs: mpsc::Sender<Job>,
}

impl Connection {
    /// Open (or create) the database at `path` on a new thread.
    pub(super) async fn open(path: &Path) -> Result<Self> {
        let path = path.to_owned();
        let (jobs, queue) = mpsc::channel::<Job>();
        let (ready, opened) = oneshot::channel();

        thread::Builder::new()
            .name("ferrite-sqlite".into())
            .spawn(move || {
                let mut conn = match rusqlite::Connection::open(&path) {
                    Ok(conn) => conn,
                    Err(e) => {
                        let _ = ready.send(Err(e));
                        return;
                    }
                };
                if ready.send(Ok(())).is_err() {
                    return;
                }
                // Ends when every handle has been dropped.
                for job in queue {
                    // A panic fails that one call (its answer is dropped, so
                    // the caller sees DatabaseClosed) and the connection stays
                    // up for the rest. An open transaction is rolled back when
                    // its guard unwinds.
                    let _ = catch_unwind(AssertUnwindSafe(|| job(&mut conn)));
                }
            })?;

        opened.await.map_err(|_| FeriteError::DatabaseClosed)??;
        Ok(Self { jobs })
    }

    /// Run `f` on the connection and wait for what it returns.
    pub(super) async fn call<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut rusqlite::Connection) -> rusqlite::Result<R> + Send + 'static,
        R: Send + 'static,
    {
        let (reply, answer) = oneshot::channel();
        self.jobs
            .send(Box::new(move |conn| {
                let _ = reply.send(f(conn));
            }))
            .map_err(|_| FeriteError::DatabaseClosed)?;
        Ok(answer.await.map_err(|_| FeriteError::DatabaseClosed)??)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "{name}-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[tokio::test]
    async fn calls_run_in_order_on_one_connection() {
        let path = temp_path("ferrite-conn-order");
        let conn = Connection::open(&path).await.unwrap();
        conn.call(|c| c.execute_batch("CREATE TABLE t (n INTEGER)"))
            .await
            .unwrap();

        // Fire them all before awaiting any: the thread still takes them in
        // the order they were sent.
        let pending: Vec<_> = (0..50)
            .map(|n| {
                let conn = conn.clone();
                tokio::spawn(async move {
                    conn.call(move |c| c.execute("INSERT INTO t VALUES (?1)", [n]))
                        .await
                })
            })
            .collect();
        for p in pending {
            p.await.unwrap().unwrap();
        }
        let count: i64 = conn
            .call(|c| c.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0)))
            .await
            .unwrap();
        assert_eq!(count, 50);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn an_sqlite_error_comes_back_as_a_database_error() {
        let path = temp_path("ferrite-conn-error");
        let conn = Connection::open(&path).await.unwrap();
        let err = conn
            .call(|c| c.execute_batch("SELECT * FROM no_such_table"))
            .await
            .unwrap_err();
        assert!(matches!(err, FeriteError::Database(_)), "{err:?}");
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn a_panicking_call_fails_alone() {
        let path = temp_path("ferrite-conn-panic");
        let conn = Connection::open(&path).await.unwrap();
        let err = conn
            .call(|_| -> rusqlite::Result<()> { panic!("boom") })
            .await
            .unwrap_err();
        assert!(matches!(err, FeriteError::DatabaseClosed), "{err:?}");
        // The connection is still there for the next call.
        let one: i64 = conn
            .call(|c| c.query_row("SELECT 1", [], |r| r.get(0)))
            .await
            .unwrap();
        assert_eq!(one, 1);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn opening_a_path_that_cannot_be_a_database_fails() {
        // A directory is not a file SQLite can open.
        let err = Connection::open(&std::env::temp_dir()).await.unwrap_err();
        assert!(matches!(err, FeriteError::Database(_)), "{err:?}");
    }
}
