
CREATE TABLE users (
  id VARCHAR(36) PRIMARY KEY,
  username VARCHAR(36) NOT NULL,
  email VARCHAR(36) NOT NULL UNIQUE,
  password VARCHAR(36) NOT NULL,
  question_id INT NOT NULL DEFAULT 1,
  points INT NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE questions (
  id SERIAL PRIMARY KEY,
  question TEXT NOT NULL,
  answers TEXT NOT NULL -- JSON array
);

INSERT INTO questions (question, answers)
VALUES
  ('What is the meaning of life?', '["42", "There is no meaning", "To be happy", "To help others"]'),
  ('What is the purpose of art?', '["To express emotions", "To make money", "To make people think", "To make people happy"]'),
  ('What is the best way to live?', '["To be free", "To be rich", "To be healthy", "To be happy"]'),
  ('Is this a random question?', '["Yes", "No", "Maybe", "I don''t know"]'),
  ('Where is the best place to live?', '["In the city", "In the country", "In the mountains", "In the beach"]');
