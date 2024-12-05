CNAD Assignment 1 Jesiah Chow

<h1>Overview</h1>
The project is a fully functional electric car-sharing system designed using Go programming language. This system incorporates multiple features such as user registration, membership-tiers, real-time vehicle reservations, billing and microservices architecture.
This application uses RESTful APIs and is backed by a relational database (MySQL) to manage data such as users, vehicles, reservations, billing, and promotions. The application may be lacking in design as it was not a priority and the features are limited due to the scope of this assignment.
<h1>Key Features</h1>
<li>User Management
    <ul>
      <li>User registration, login and authentication(email verification)</li>
      <li>Membership tiers (Basic, Premium, VIP) with different benfits i.e. discount rates</li>
      <li>User profile management, including rental history</li>
    </ul>
  </li>
  <li>Vehicle Reservation System
    <ul>
      <li>Real-time vehicle availability and booking.</li>
      <li>Booking modification and cancellation options with a specified policy</li>
    </ul>
  </li>
  <li>Bill and Payment processing
    <ul>
      <li>Tier-based pricing and promotional discounts</li>
      <li>Real-time billing calculation and updates</li>
      <li>Invoicing and receipts generation</li>
    </ul>
  </li>
  <li>Microservices Architecture
    <ul>
      <li>Service decomposition into distinct services (User Service, Vehicle Service, Billing Service etc.).</li>
      <li>Inter-service communication via RESTful APIs.</li>
    </ul>
  </li>
   <li>Database Management
    <ul>
      <li>Relational database design for structured data storage (users, vehicles, reservations, etc.).</li>
    </ul>
  </li>
<h1>Design Considerations for Microservices</h1>
<li>User service: Responsible for managing user registration, authentication, and profile management. In addition managing the membership of the user. Communicates with database to store user information.</li>
<li>Vehicle service: Responsible for managing vehicles availablilty, hourly rates, and status. Ensures vehicles are available for booking.</li>
<h1>Architecture Diagram</h1>


