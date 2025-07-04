# 🚀 Full-Stack Flask Web Application with Redis and Nginx


[https://web-production-efd4e.up.railway.app/](https://web-production-efd4e.up.railway.app/)

**Author:** Matthew Reiley  
**Date:** November 18, 2024  


---

## 📢 Project Overview

This project showcases a robust, scalable full-stack web application built with **Flask**, **Redis**, and **Nginx**. It combines modern backend development with production-ready deployment strategies to deliver a seamless user experience with secure session management and high performance.

At its core, users can create accounts, log in, and manage profiles with features like email verification, password reset, and role-based access control — all backed by fast, reliable Redis session storage and served through Nginx’s powerful reverse proxy and load balancing.

---

## 🎯 Key Features

- **User Authentication:** Secure registration, login, email verification, and password reset flows.  
- **Role-Based Access Control:** Different permissions for users to access various sections of the app.  
- **Redis-Powered Session Management:** Scalable, fast session storage with persistent login states.  
- **Production-Ready Deployment:**  
  - Nginx as a reverse proxy to handle HTTPS, static files, and load balancing.  
  - SSL/TLS encryption for secure user connections.  
- **Dockerized Infrastructure:** Easily reproducible environments with Redis, Flask app, and Nginx running in containers.

---

## 🛠️ Tech Stack

| Component           | Description                                   |
|---------------------|-----------------------------------------------|
| **Flask**           | Lightweight Python web framework for backend logic |
| **Redis**           | In-memory data store for fast, scalable session management |
| **Nginx**           | Reverse proxy, SSL termination, and load balancer |
| **Docker**          | Containerization platform for easy deployment |
| **Gunicorn**        | WSGI HTTP server to serve the Flask app efficiently |

---

## 🚀 Getting Started

### Prerequisites

- Docker & Docker Compose installed  
- (Optional) Access to your own Redis server if not using Docker  

### Run Locally with Docker

```bash
# Clone the repository
git clone https://github.com/yourusername/your-repo-name.git
cd your-repo-name

# Build and start containers
docker-compose up --build

