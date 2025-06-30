# Use official Rust image
FROM rust:1.75

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

# Install dependencies and build
RUN cargo build --release

# Expose port
EXPOSE 3000

# Run the application directly
CMD ["cargo", "run", "--release"]
