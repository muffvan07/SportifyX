# SportifyX API - E-commerce Platform

SportifyX API is the backend of an advanced e-commerce platform designed for sportswear and sports equipment. Built using .NET 8, this API provides all the necessary functionality for managing users, products, cart, orders, and more. It follows best practices such as SOLID principles, REST API standards, and clean architecture.

## Features

- **User Authentication & Authorization**
  - User registration, login, password recovery, and role-based access control.
  - Email and phone number verification.
  - JWT-based authentication.
  - Multi-factor authentication (MFA) using OTP.

- **Product Catalog**
  - Browse products by categories like sportswear, footwear, and equipment.
  - Filter products by category, brand, gender, price, and material.
  - View detailed product information, including images, specs, reviews, and ratings.
  - Check product inventory and stock availability.
  - Add products to cart or wishlist.

- **Shopping Cart & Wishlist**
  - Add, update, and remove products from cart.
  - Manage favorite products in the wishlist.

- **Order Management**
  - Track and manage orders from cart to checkout.

- **Admin Dashboard**
  - Manage users, roles, products, orders, and more.

## Technologies Used

- **Backend Framework:** .NET 8
- **API Communication:** RESTful API
- **Database:** SQL Server (using Entity Framework Core)
- **Authentication:** JWT Tokens, Email & SMS verification
- **Logging & Error Handling:** Custom logging, exception handling, and response wrapping
- **Design Principles:** SOLID principles, Clean Architecture

## Project Structure

1. **SportifyX.API** - Contains the API controllers and routes for the application.
2. **SportifyX.Application** - Implements the business logic and services.
3. **SportifyX.Domain** - Defines the models and entities.
4. **SportifyX.Infrastructure** - Contains the repositories and database logic.
5. **SportifyX.Common** - Reusable utilities, constants, and shared components.

## Setup & Installation

### Prerequisites

- .NET 8 SDK
- SQL Server or any compatible relational database
- IDE like Visual Studio or Visual Studio Code

### Clone the repository

```bash
git clone https://github.com/yourusername/sportifyx-api.git
cd sportifyx-api
