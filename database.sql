CREATE TABLE users (
    id UUID PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE friends (
    user_id UUID REFERENCES users(id),
    friend_id UUID REFERENCES users(id),
    PRIMARY KEY (user_id, friend_id)
);

CREATE TABLE messages (
    id UUID PRIMARY KEY,
    from_user_id UUID REFERENCES users(id),
    to_user_id UUID REFERENCES users(id),
    message TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);