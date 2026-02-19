-- PostgreSQL test database for QuerySense
-- Creates tables with realistic data for generating EXPLAIN plans

-- Orders table (large, for testing seq scan detection)
CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    total DECIMAL(10, 2) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Order items (for testing join performance)
CREATE TABLE order_items (
    id SERIAL PRIMARY KEY,
    order_id INTEGER NOT NULL REFERENCES orders(id),
    product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 1,
    price DECIMAL(10, 2) NOT NULL
);

-- Products table
CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(100),
    price DECIMAL(10, 2) NOT NULL,
    stock INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255),
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Insert sample data (250k orders for realistic testing)
INSERT INTO users (email, name, status)
SELECT 
    'user' || i || '@example.com',
    'User ' || i,
    CASE WHEN random() < 0.9 THEN 'active' ELSE 'inactive' END
FROM generate_series(1, 10000) AS i;

INSERT INTO products (name, category, price, stock)
SELECT 
    'Product ' || i,
    CASE (i % 5)
        WHEN 0 THEN 'Electronics'
        WHEN 1 THEN 'Clothing'
        WHEN 2 THEN 'Books'
        WHEN 3 THEN 'Home'
        ELSE 'Other'
    END,
    (random() * 1000)::DECIMAL(10, 2),
    (random() * 1000)::INTEGER
FROM generate_series(1, 1000) AS i;

INSERT INTO orders (customer_id, status, total, created_at)
SELECT 
    (random() * 9999 + 1)::INTEGER,
    CASE (random() * 10)::INTEGER
        WHEN 0 THEN 'pending'
        WHEN 1 THEN 'processing'
        WHEN 2 THEN 'shipped'
        WHEN 3 THEN 'delivered'
        ELSE 'completed'
    END,
    (random() * 500 + 10)::DECIMAL(10, 2),
    NOW() - (random() * 365 || ' days')::INTERVAL
FROM generate_series(1, 250000) AS i;

INSERT INTO order_items (order_id, product_id, quantity, price)
SELECT 
    (random() * 249999 + 1)::INTEGER,
    (random() * 999 + 1)::INTEGER,
    (random() * 5 + 1)::INTEGER,
    (random() * 100 + 5)::DECIMAL(10, 2)
FROM generate_series(1, 500000) AS i;

-- Analyze tables for accurate statistics
ANALYZE orders;
ANALYZE order_items;
ANALYZE products;
ANALYZE users;

-- Create some indexes (but leave orders.status unindexed for testing)
CREATE INDEX idx_order_items_order_id ON order_items(order_id);
CREATE INDEX idx_order_items_product_id ON order_items(product_id);
CREATE INDEX idx_products_category ON products(category);
CREATE INDEX idx_users_email ON users(email);

-- Helpful comment
COMMENT ON DATABASE testdb IS 'QuerySense test database with 250k orders';
