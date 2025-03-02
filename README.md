# SportifyX - E-commerce Platform

SportifyX is an advanced e-commerce platform for sportswear and sports equipment, built using .NET 8. This project implements various core functionalities like user authentication, product catalog, shopping cart, wishlist, order management, and more. It follows best practices such as SOLID principles, REST API standards, and clean architecture.

## Features

- **User Authentication & Authorization**
  - User registration, login, password recovery, and role-based access control.
  - Multi-factor authentication (MFA) using OTP.
  - Email and phone number verification.

- **Product Catalog**
  - Browse products by categories such as sportswear, footwear, and equipment.
  - Filter products by category, brand, gender, price, and material.
  - View detailed product information, including images, specs, reviews, and ratings.
  - Check product inventory and stock availability.
  - Add products to the cart or wishlist.

- **Shopping Cart & Wishlist**
  - Manage cart items.
  - Save favorite products to wishlist for future purchases.

- **Order Management**
  - Track and manage orders from cart to checkout.
  - Payment gateway integration.

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

1. **SportifyX.API** - Contains the API controllers and routes.
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
git clone https://github.com/yourusername/sportifyx.git
cd sportifyx
