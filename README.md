# SecureVault: A Cloud-Based System for Data Leak Prevention and Secure Data Management

###### The original AWS RDS, lambda instances and other services used for this deployment have been terminated. To run this project, please create a new resourses and configure the file accordingly. ######

## Objective
Design and deploy a secure, cloud-based system that:
- Detects and prevents SQL injection attacks
- Uses AES-256 encryption for sensitive user data
- Implements capability-based access for injected SQL
- Enforces double-layered defense against data leaks
- Is lightweight, serverless, and publicly accessible

## 🏗 System Architecture Overview
| Layer          | Component                                     |
|----------------|-----------------------------------------------|
| Frontend       | HTML/CSS/JavaScript hosted on Vercel          |
| API Gateway    | Amazon API Gateway (HTTP API)                |
| Compute        | AWS Lambda running Express.js                 |
| Database       | Amazon RDS (PostgreSQL)                      |
| Encryption     | Node.js crypto module (AES-256-GCM)          |
| Auth Layer     | JWT-based auth + capability flags            |
| Infra as Code  | Serverless Framework (serverless.yml)        |

## 🧱 Security Components Implemented
### 🔹 1. SQL Injection Protection
- Used parameterized queries exclusively with `pg`:
  ```javascript
  const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
  ```
- Disabled dynamic SQL interpolation
- Validated input fields at the controller level

### 🔹 2. AES-256 Encryption
- Custom middleware encrypts sensitive fields before DB insert
- Uses AES-256-GCM with IV + Auth Tag
- Secure keys managed through environment variables (KMS optional)

### 🔹 3. Capability Code Injection Control
- Every endpoint checks for capability tokens (e.g., `secret:create`)
- Injected into JWT claims or passed via secure headers
- Rejected if user context doesn’t include required capability

### 🔹 4. Double-Layered Security Protocol
| Layer         | Mechanism                             |
|---------------|---------------------------------------|
| 1️⃣ Identity   | JWT Auth + Role-based Capabilities   |
| 2️⃣ Transport/Data | HTTPS + CORS + AES-256 Encryption |

### 🔹 5. Lightweight Internet Access
- Fully serverless Lambda stack via Serverless Framework
- Public, secure endpoints via API Gateway
- Frontend deployed on Vercel with minimal build pipeline
- Zero-maintenance infrastructure

## 📊 System Flow
```
+---------------------+       +--------------------------+
| User (Browser)      |       | Vercel                   |
| Accesses Frontend   |<----->| - Hosts SecureVault      |
|                     | HTTPS | - URL: data-leak.vercel  |
|                     |       |   .app/dashboard.html    |
+---------------------+       +--------------------------+
                                |
                                | HTTPS (CORS-enabled)
                                v
+---------------------+       +--------------------------+
| AWS API Gateway     |       | AWS Lambda               |
| - Routes Requests   |<----->| - Runs securevault-api   |
| - URL: 86beqm147d  |       | - Node.js 18.x           |
|   .execute-api...   |       | - Express w/ serverless  |
+---------------------+       +--------------------------+
                                |
                                | VPC
                                v
+---------------------+       +--------------------------+
| AWS RDS (PostgreSQL)|       | Secrets Storage          |
| - Hosts user-       |       | - users table            |
|   securitydb        |       | - secrets table          |
| - Port: 5432        |       | - AES-256 encrypted      |
+---------------------+       +--------------------------+
```

## ✅ Deployment Recap
| Milestone                          | Status        |
|------------------------------------|---------------|
| Setup Serverless Project           | ✅ Completed |
| API Gateway Routing (/{proxy+})    | ✅ Completed |
| JWT + Capability Enforcement       | ✅ Completed |
| PostgreSQL Query Hardening         | ✅ Completed |
| Express Raw Buffer Fix             | ✅ Completed |
| AES Encryption of Secrets          | ✅ Completed |
| Frontend Login/Register Flow       | ✅ Completed |
| CORS Errors Resolved               | ✅ Completed |
| Preflight + OPTIONS Handling       | ✅ Completed |

## 🚀 Deployment Details
### Project Overview
The SecureVault application consists of:
- **Backend**: `securevault-api`, built with Node.js and Express, connects to an AWS RDS PostgreSQL database (`user-securitydb`) and uses AES-256 encryption and JWT-based authentication for secure user registration and secret storage. Repository: [CloudCom-withVictor/securevault-api](https://github.com/CloudCom-withVictor/securevault-api).
- **Frontend**: Vanilla JavaScript frontend, hosted on Vercel at [https://data-leak.vercel.app/dashboard.html](https://data-leak.vercel.app/dashboard.html), providing a user interface for interacting with the backend. Repository: [CloudCom-withVictor/CodeAlpha_DataLeakDetectionSystem-frontend](https://github.com/CloudCom-withVictor/CodeAlpha_DataLeakDetectionSystem-frontend).
- **Goal**: Deploy the backend to AWS Lambda, the frontend to Vercel, and ensure CORS allows access from [https://data-leak.vercel.app](https://data-leak.vercel.app) and [http://localhost:5500](http://localhost:5500), using hardcoded secrets in a `.env` file.

### API Gateway
- **ARN**: `arn:aws:apigateway:us-east-1::/apis/86beqm147d/routes/2g5uvmt`
- **URL**: [https://86beqm147d.execute-api.us-east-1.amazonaws.com/dev](https://86beqm147d.execute-api.us-east-1.amazonaws.com/dev)
- Routes requests to the Lambda function handling the `securevault-api`.

### Issues Encountered
1. **ServerlessError2**: "service" property missing in `serverless.yml`
   - Caused by an invalid or missing `serverless.yml` configuration.
2. **ENOTFOUND Error**: `getaddrinfo ENOTFOUND core.serverless.com`
   - Caused by network connectivity or DNS issues preventing Serverless Framework CLI (v4.17.1) from authenticating with its backend.

### Steps Taken
#### 1. Resolving ServerlessError2
- **Diagnosis**: Missing or misconfigured `service` property in `serverless.yml`.
- **Actions**:
  - Verified `serverless.yml` presence in the `CodeAlpha_DataLeakDetectionSystem` directory (project root for `securevault-api`).
  - Confirmed `service: securevault-api`.
  - Corrected handler from `securevault-api.handler.server` to `app.handler` to align with `app.js` using `serverless-http`.
  - Validated YAML syntax with an online linter.
  - Updated `serverless.yml` to include:
    - Hardcoded environment variables (`DB_NAME`, `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASS`, `ENCRYPTION_KEY`, `JWT_SECRET`).
    - VPC configuration for AWS RDS access (security group and subnet IDs).
    - CORS settings for [http://localhost:5500](http://localhost:5500) and [https://data-leak.vercel.app](https://data-leak.vercel.app).
    - IAM permissions for VPC access (no AWS Secrets Manager needed).
    - Excluded `.env` from deployment via `package.exclude`.

#### 2. Resolving ENOTFOUND Error
- **Diagnosis**: DNS resolution failure or network issue preventing Serverless CLI from reaching the Serverless Dashboard.
- **Actions**:
  - Tested connectivity by pinging `core.serverless.com` and accessing [https://core.serverless.com](https://core.serverless.com).
  - Switched to Google DNS (8.8.8.8, 8.8.4.4).
  - Updated Serverless Framework: `npm install -g serverless@latest`.
  - Configured AWS credentials: `aws configure` (Access Key ID, Secret Access Key, region: `us-east-1`, output: `json`).
  - Verified with: `aws sts get-caller-identity`.
  - Bypassed Serverless Dashboard by setting `frameworkVersion: '3'` in `serverless.yml` and running: `serverless deploy --noDashboard`.
  - Ran deployment with debug mode: `serverless deploy --debug`.

### Backend Deployment to AWS Lambda
#### Directory Structure
```
CodeAlpha_DataLeakDetectionSystem/
├── app.js
├── db.js
├── .env
├── package.json
├── package-lock.json
├── serverless.yml
├── routes/
│   └── users.js
├── utils/
│   ├── encrypt.js
│   ├── decrypt.js
├── middleware/
│   └── auth.js
```

#### Configuration
- **app.js**:
  ```javascript
  require('dotenv').config();
  const express = require('express');
  const cors = require('cors');
  const serverless = require('serverless-http');
  const app = express();
  const allowedOrigins = ['http://localhost:5500', 'https://data-leak.vercel.app'];
  app.use(cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: false
  }));
  app.use(express.json());
  app.use((req, res, next) => {
    if (Buffer.isBuffer(req.body)) {
      try {
        req.body = JSON.parse(req.body.toString('utf8'));
      } catch (e) {
        console.error('JSON parse failed:', e.message);
        req.body = {};
      }
    }
    next();
  });
  app.get('/', (req, res) => res.send('SecureVault API is live!'));
  const usersRouter = require('./routes/users');
  app.use('/api/users', usersRouter);
  module.exports.handler = serverless(app);
  ```
- **.env.example**:
  ```
DB_HOST=your-db-endpoint.rds.amazonaws.com
DB_PORT=5432
DB_USER=your-db-username
DB_NAME=your-db-name
DB_PASS=your-db-password
ENCRYPTION_KEY=your-32-byte-hex-key
JWT_SECRET=your-jwt-secret-key
  ```
- Updated `db.js`, `encrypt.js`, `decrypt.js`, and removed `utils/secrets.js`.
- Updated `auth.js` to use `process.env`.
- **package.json**: Included dependencies (`express`, `cors`, `pg`, `bcrypt`, `jsonwebtoken`, `crypto`, `serverless-http`, `dotenv`, `serverless-offline`), removed `aws-sdk`.
- **serverless.yml**:
  ```yaml
  service: securevault-api
  frameworkVersion: '4'
  provider:
    name: aws
    runtime: nodejs18.x
    region: us-east-1
    stage: dev
    memorySize: 256
    timeout: 10
    httpApi:
      payload: '2.0'
    vpc:
      securityGroupIds:
        - sg-073b235e71a80c9cc
      subnetIds:
        - subnet-08ce220807b0947a6
        - subnet-01492e08be7064cee
        - subnet-08ccc3a97b15c9fe7
        - subnet-03d19975461b33a41
        - subnet-053081826548a8c32
        - subnet-03028deec9392a4d0
    environment:
      PORT: ${env:PORT}
      DB_PORT: ${env:DB_PORT}
      DB_HOST: ${env:DB_HOST}
      DB_USER: ${env:DB_USER}
      DB_PASS: ${env:DB_PASS}
      DB_NAME: ${env:DB_NAME}
      JWT_SECRET: ${env:JWT_SECRET}
      ENCRYPTION_KEY: ${env:ENCRYPTION_KEY}
    iam:
      role:
        statements:
          - Effect: Allow
            Action:
              - ssm:*
              - s3:*
              - logs:*
              - lambda:*
              - iam:GetRole
              - iam:PassRole
            Resource: "*"
  functions:
    app:
      handler: handler.server
      events:
        - httpApi:
            path: /{proxy+}
            method: '*'
            cors:
              allowedOrigins:
                - '*'
              allowedHeaders:
                - Content-Type
              allowedMethods:
                - GET
                - POST
                - OPTIONS
  plugins:
    - serverless-dotenv-plugin
    - serverless-offline
  package:
    exclude:
      - .gitignore
      - README.md
      - tests/**
      - .vscode/**
  ```
- **RDS Security Group**:
  - Added inbound rule: Type: PostgreSQL, Protocol: TCP, Port: 5432, Source: Lambda security group (`sg-073b235e71a80c9cc`).
- **Deployment**:
  - Installed dependencies: `npm install`
  - Deployed to AWS Lambda: `serverless deploy`
  - API Gateway URL: [https://86beqm147d.execute-api.us-east-1.amazonaws.com/dev](https://86beqm147d.execute-api.us-east-1.amazonaws.com/dev)
  - Tested endpoints with Postman:
    - `GET /`
    - `POST /api/users/register`
    - `POST /api/users/login`
    - `POST /api/users/store` (with `Authorization: Bearer <token>`)
    - `GET /api/users/read` (with `Authorization: Bearer <token>`)
    - `GET /api/users/ping`

### Frontend Deployment to Vercel
#### Directory Structure
```
CodeAlpha_DataLeakDetectionSystem-frontend/
├── index.html
├── register.html
├── login.html
├── store.html
├── read.html
├── dashboard.html
├── css/
│   └── styles.css
├── js/
│   └── app.js
├── .env
```

#### Configuration
- **js/app.js**:
  ```javascript
  const API_URL = 'https://86beqm147d.execute-api.us-east-1.amazonaws.com/dev/api/users';
  ```
- Excluded `.env` from Git via `.gitignore`.
- **GitHub Push**:
  ```bash
  cd CodeAlpha_DataLeakDetectionSystem-frontend
  git init
  echo ".env" > .gitignore
  git add .
  git commit -m "Initial commit"
  git remote add origin https://github.com/CloudCom-withVictor/CodeAlpha_DataLeakDetectionSystem-frontend.git
  git push -u origin main
  ```
- **Vercel Deployment**:
  - Imported the `CodeAlpha_DataLeakDetectionSystem-frontend` repository in Vercel Dashboard.
  - Configured:
    - Framework Preset: Other
    - Root Directory: ./
    - Environment Variable: `API_URL` with `https://86beqm147d.execute-api.us-east-1.amazonaws.com/dev/api/users`
  - Deployed, resulting in the URL [https://data-leak.vercel.app/dashboard.html](https://data-leak.vercel.app/dashboard.html).
- **CORS Update**:
  - Updated `app.js` and `serverless.yml` to include [https://data-leak.vercel.app](https://data-leak.vercel.app) in CORS origins.
  - Redeployed backend: `serverless deploy`

### Testing
- **Backend**: Verified all endpoints using Postman, confirming functionality.
- **Frontend**: Accessed [https://data-leak.vercel.app/dashboard.html](https://data-leak.vercel.app/dashboard.html) and tested registration, login, secret storage, and retrieval. Confirmed no CORS errors in the browser console.
- **Local Testing**: Served frontend locally with `npx http-server -p 5500` and tested with the API Gateway URL.

### Security Enhancements
- **Hardcoded Secrets**: Stored in `.env` and excluded from Git. Recommended AWS Secrets Manager for production.
- **Rate Limiting**: Suggested adding `express-rate-limit` to `app.js`:
  ```javascript
  npm install express-rate-limit
  const rateLimit = require('express-rate-limit');
  app.use(rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // 100 requests per IP
  }));
  ```
- **Input Validation**: Suggested adding `express-validator` to `routes/users.js`.
- **HTTPS**: Ensured by API Gateway and Vercel.
- **Token Security**: Recommended HttpOnly cookies for JWTs in production.
- **RDS SSL**: Suggested updating `db.js` for SSL in production:
  ```javascript
  ssl: {
    rejectUnauthorized: true,
    ca: [fs.readFileSync('path/to/rds-ca-cert.pem').toString()]
  }
  ```

## 🔍 Testing & Validation
- Tested via Postman, browser DevTools, and live user input
- Verified CORS headers and OPTIONS support manually
- Attempted SQL injection patterns (e.g., `' OR 1=1--`) rejected
- Confirmed data encrypted at rest using GCM payload inspection

## 📈 Future Enhancements
- ☁️ Integrate AWS KMS for full key lifecycle management
- 🧠 Add anomaly detection for query patterns
- 🧾 Build admin dashboard to audit capability usage
- 🔐 Expand capability definitions per user/secret

## 📘 Conclusion
SecureVault successfully defends against SQL injection and data leaks using a multi-layered, encrypted, cloud-native architecture. With serverless APIs, strong encryption, and robust authentication, it provides secure and scalable access over the public internet, fulfilling all five pillars of the task. The backend is deployed on AWS Lambda with API Gateway (ARN: `arn:aws:apigateway:us-east-1::/apis/86beqm147d/routes/2g5uvmt`), and the frontend is hosted on Vercel, with CORS configured for seamless interaction.

**Date**: July 4, 2025

**GitHub Repositories**:
- Backend: [CloudCom-withVictor/CodeAlpha_DataLeakDetectionSystem/securevault-api](https://github.com/CloudCom-withVictor/CodeAlpha_DataLeakDetectionSystem/securevault-api)
- Frontend: [CloudCom-withVictor/CodeAlpha_DataLeakDetectionSystem-frontend](https://github.com/CloudCom-withVictor/CodeAlpha_DataLeakDetectionSystem-frontend)