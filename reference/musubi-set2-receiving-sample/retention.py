"""Adapter-local transaction composition; the Inbox contract is unchanged."""
from contextlib import contextmanager


def batch_inbox_type(inbox_type):
    class BatchInbox(inbox_type):
        @contextmanager
        def transaction(self):
            if not self.db.in_transaction:
                with super().transaction():
                    yield
                return
            # Keep every core validation and rollback boundary while an adapter
            # batch holds the writer lock. No individual step commits the batch.
            self.db.execute('SAVEPOINT musubi_retention_step')
            try:
                yield
                self.db.execute('RELEASE musubi_retention_step')
            except BaseException:
                if self.db.in_transaction:
                    self.db.execute('ROLLBACK TO musubi_retention_step')
                    self.db.execute('RELEASE musubi_retention_step')
                raise
    return BatchInbox
