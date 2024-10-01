from datetime import datetime, timezone
from uuid import uuid4, UUID
from marketing import files

forbidden_ids = [f["metadata"]["id"] for f in files]

class FileTooBigException(Exception):
    pass

class PathTraversalAttemptDetectedException(Exception):
    pass

class StringTooLongException(Exception):
    pass

class Forbidden(Exception):
    pass

class FileMetadata:
    def __init__(
            self,
            author,
            filename,
            description,
            id = None,
    ):
        if len(author) > 50 or \
           len(filename) > 50 or \
           len(description) > 150:
            raise StringTooLongException()
        self.creation_time = datetime.now(tz=timezone.utc)

        self.author = author
        self.filename = filename
        self.init = id in forbidden_ids
        basedir = "/company" if self.init else "/tmp"
        self.path = f"{basedir}/{filename}"
        self.description = description
        self.id = str(UUID(id, version=4)) if id is not None else str(uuid4())

    def write(self, collection, content):
        if self.id in forbidden_ids and not self.init:
            raise ValueError("Use of forbidden id")

        collection.insert_one(vars(self))

        if "./" in self.path:
            raise PathTraversalAttemptDetectedException()
        if len(content) > 200:
            raise FileTooBigException()
        with open(self.path, "w") as f:
            f.write(content)

    def read(self, offset, addr):
        import hashlib
        with open(self.path) as f:
            content = f.read().format(hashlib.sha1(b"ABCDEFGH").hexdigest()[:8])
            return content[offset:]

    # honeypot
    #def read(self, offset):
    #    with open(self.path) as f:
    #        f.seek(offset)
    #        return f.read()