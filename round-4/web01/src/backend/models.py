from datetime import datetime, timezone


class Post:
    def __init__(
            self,
            id,
            recipient,
            title,
            text,
    ):
        self.creation_time = datetime.now(tz=timezone.utc)
        self.id = id
        self.recipient = recipient
        self.title = title
        self.text = text


class Key:
    def __init__(
            self,
            id,
            key,
    ):
        self.creation_time = datetime.now(tz=timezone.utc)
        self.id = id
        self.key = key