Sure! Here's the README file content for your project:

```markdown
# YouApp Backend

This is the backend for the YouApp application, built with Nest.js, MongoDB, and Node.js. It includes JWT authentication, real-time communication with Socket.io, and comprehensive API documentation with Swagger.

## Prerequisites

- Node.js (v14 or higher)
- MongoDB

## Installation

1. Clone the repository:

   ```
   git clone https://github.com/Romajisen/Youapp.git
   cd youapp-backend
   ```

2. Install the dependencies:

   ```
   npm install
   ```

3. Create a `.env` file in the root directory and add the following environment variables:

   ```env
   MONGODB_URI=mongodb://localhost:27017/youapp
   JWT_SECRET=yourSecretKey
   ```

## Running the Application

1. Start the MongoDB server:

   ```
   mongod
   ```

2. Start the Nest.js application:

   ```
   npm run start:dev
   ```

   This will start the server with Hot Module Replacement (HMR) enabled, allowing the server to automatically reload when you change the code.

## API Documentation

The API documentation is available at `http://localhost:3000/api`.

## Running Tests

1. Run unit tests:

   ```
   npm run test
   ```

2. Run end-to-end tests:

   ```
   npm run test:e2e
   ```

## Project Structure

```
youapp-backend/
├── src/
│   ├── auth/
│   │   ├── auth.module.ts
│   │   ├── auth.service.ts
│   │   ├── jwt.strategy.ts
│   │   ├── jwt-payload.interface.ts
│   ├── common/
│   │   ├── dto/
│   │   │   ├── create-user.dto.ts
│   │   │   ├── login.dto.ts
│   │   │   ├── create-message.dto.ts
│   ├── user/
│   │   ├── user.module.ts
│   │   ├── user.service.ts
│   │   ├── user.controller.ts
│   │   ├── user.schema.ts
│   ├── chat/
│   │   ├── chat.module.ts
│   │   ├── chat.service.ts
│   │   ├── chat.controller.ts
│   │   ├── chat.gateway.ts
│   │   ├── chat.schema.ts
│   ├── app.module.ts
│   ├── main.ts
│   ├── swagger.config.ts
│   ├── cors.config.ts
├── test/
│   ├── app.e2e-spec.ts
│   ├── jest-e2e.json
├── .env
├── docker-compose.yml
├── Dockerfile
├── package.json
├── tsconfig.json
├── tsconfig.build.json
├── license
├── webpack-hmr.config.js
├── README.MD
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License.
```

You can copy this content into a `README.md` file in your project directory. Let me know if you need any further assistance!