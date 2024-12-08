CNAD Assignment 1 Jesiah Chow

<h1>Overview</h1>
The project is a fully functional electric car-sharing system designed using Go programming language. This system incorporates multiple features such as user registration, membership-tiers, real-time vehicle reservations, billing and microservices architecture.
This application uses RESTful APIs and is backed by a relational database (MySQL) to manage data such as users, vehicles, reservations, billing, and promotions.
<h1>Key Features</h1>
<li>User Management
    <ul>
      <li>User registration, login and authentication(email verification)</li>
      <li>Membership tiers (Basic, Premium, VIP) with different benefits i.e. discount rates</li>
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

The microservices architecture for this vehicle reservation system is designed with modularity, scalability, and clarity of responsibility in mind. Each service focuses on a specific domain of the application:

<li>User service: Responsible for managing user registration, authentication, and profile management. In addition managing the membership of the user. Communicates with database to store user information.</li>
<li>Vehicle service: Responsible for managing vehicles availabililty, hourly rates, and status. Ensures vehicles are available for booking.</li>
<li>Reservation service: Responsible for managing reservations, listing reservation details, modifications and cancellations of reservation and calculating total price depending on user</li>
<li>Billing service: Responsible for managing billing and payments. List the details and tallying promotional discount and membership discount to calculate the final price needed to be paid</li>
<li>Promotion service: Responsible for managing promotions. Manages the availability and creation of promotional codes, discount rates and the availability period.</li>
Each service is independent, allowing for easier scaling and maintenance, and they communicate with each other using RESTful APIs to ensure loose coupling.
<h1>Architecture Diagram</h1>

![cnad-architectural-diagram](https://github.com/user-attachments/assets/10a7683b-9ecf-4631-aac4-49be64660e56)

Link to view the diagram: https://lucid.app/publicSegments/view/a636e470-beea-40dd-a797-45f99157fdc1/image.png
<h2>Database Design</h2>

1. User Service Database
   Tables: users and membership_tiers

- The User Service handles all user-related data, such as user profiles, authentication and membership details. Combining users and membership tiers in this database ensures logical grouping of closely related entities.
- All operations related to user accounts, such as verifying emails, retrieving membership benefits like discounts, and updating user details, can be performed within the same service without cross-service calls.
- Keeping users and membership tiers together, helps avoid unneccesary API calls to other services for retrieving membership-related information.
- User operations scale independently from from other services, so keeping a separate database allows operations to scale as needed without impacting other services.

2. Vehicle Service Database
   Tables: vehicles

- The Vehicle Service is responsible for managing data of vehicles within the car-sharing system. This includes their status(available, reserved, in maintenance), location and hourly rate. This ensures data separation from other services and increase scalability.
- Vehicle operations such as retrieving available vehicles or updating vehicle status remains isolated, reducing the risk of conflicting operations with other services.
- The Vehicle Service can scale independently to handle operations like frequent vehicle status updates or querying for vehicle availability.

3. Reservation Service Database
   Tables: reservations

- The Reservation Service is responsible for managing reservations, including start times and end times, total price (excluding membership and promotional discounts), and reservation status. Storing reservation in a separate database allows it to independently handle reservation-related business logic.
- The reservation table references the users table in User Service and vehicles in Vehicle Service. These foreign key relationships ensure the integrity of reservation data without duplicating user or vehicle information.
- Keeping reservation data isolated avoids unneccassary conflicts with billing or promotion services.
- Reservation operations such as creating, modifying, and cancelling reservations, often involve high transaction loads. Having a dedicated database ensures that these operations do not affect the performance of other services.

4. Billing Service Database
   Tables: invoices

- The Billing service handles financial operations, including the calculation of the final amounts, applying discounts, and storing payment status. Storing invoices in a dedicated database ensures these operations are isolated from other services such as Reservation Service.
- The invoices table includes details needed for invoicing (e.g. vehicle information, discounts, and timestamps). This avoids the need to query multiple services when generating invoices.
- By keeping the Billing Service separate, billing operations such as payment processing and invoice generation are isolated from other services like Reservation and User Management. This separation ensures that these processes do not interfere with reservation status updates or user management workflows. Once payment is confirmed, the Billing Service communicates with the Reservation Service to update the specific reservation status to 'completed,' without impacting the functionality of other services. In addition, to Vehicle Services to update the specific vehicle status to 'available'.

5. Promotion Service Database
   Tables: promotions

- Promotions are managed independently of users, reservations and vehicles. A dedicated database ensures that promotional logic remains encapsulated.
- Promotional data, such as discount rates and active periods can be updated without affecting the rest of the system.
- When applying promotions, the service can quickly validate active promotions and calculate discounts without querying user or billing data.
- Promotions can involve thorough validation during billing. A separate database allows this service to handle such operations efficiently without affecting other system parts.

<h1>Instructions for Setting Up and Running Microservices</h1>
<h2>Pre-requisites</h2>

- Go (1.18 or later) - The programming language used for the microservices
- MySQL - Database for storing application data
- Postman/cURL (optional) - for testing REST APIs

1. clone the repository: Clone the project to your local machine
2. Install dependencies

- go get github.com/gorilla/mux
- go get github.com/gorilla/handlers
- go get github.com/gorilla/sessions
- go get github.com/jung-kurt/gofpdf/v2
  others are part of go standard library

3. Use the MySQL scripts inside the repository and execute inside your MYSQL to initialize the databases in your MySQL instance.

4. Enable CORS on your browser before running the files

5. Run the Go files
   here is the command to run the Go files:

- go run .
