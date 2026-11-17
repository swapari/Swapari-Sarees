# Security Specification — Swapari Saree

## 1. Data Invariants
1. **Default Deny**: All unmatched paths across Firestore are unconditionally denied (`allow read, write: if false;`).
2. **Saree Schema Integrity**: Every document in `/sarees/{sareeId}` must strictly contain required keys `['id', 'name', 'price', 'image_url', 'in_stock', 'category']` and allowed keys `['id', 'name', 'price', 'image_url', 'in_stock', 'category', 'reviews']`, where `id == sareeId`, `sareeId` matches `^[a-zA-Z0-9_\-]+$` (`size <= 128`), `name` is a string (`1..120` chars), `price` is a number (`0..1000000`), `image_url` is a string (`1..250000` chars), `in_stock` is a boolean, `category` is a string (`1..60` chars), and optional `reviews` is a bounded list (`size <= 50`) of validated review maps (`id`, `reviewerName`, `rating` 1..5, `comment` 1..400 chars, `date`).
3. **Admin & Verified Customer Mutations**:
   - Only verified administrators (`isAdmin()`, authorized for `preetiharde8b@gmail.com` and runtime bootstrap `sujeetharde5@gmail.com`) may create new catalog items, toggle `in_stock`, edit core catalog fields, or delete saree inventory records.
   - Any verified authenticated user (`isVerifiedUser()`) may append/update the bounded `reviews` array on `/sarees/{sareeId}` via the dedicated review update action (`incoming().diff(existing()).affectedKeys().hasOnly(['reviews'])`).
4. **Action-Based Partial Updates**: Updates on `/sarees/{sareeId}` must validate the complete resulting document via `isValidSaree(incoming(), sareeId)`, keep immutable `id` unchanged (`incoming().id == existing().id`), and restrict modified keys via `affectedKeys().hasOnly(...)` to:
   - Action 1 (Stock Toggle): `['in_stock']` by `isAdmin()`
   - Action 2 (Customer Review Submission): `['reviews']` by `isVerifiedUser()`
   - Action 3 (Full Catalog Update): `['name', 'price', 'image_url', 'in_stock', 'category', 'reviews']` by `isAdmin()`
5. **PII & Admin Isolation**: The `/admins/{adminId}` collection stores no raw PII and restricts `get` to the owner or verified admin, with `create`/`update`/`delete` restricted to verified bootstrapped admin.

## 2. The "Dirty Dozen" Payloads

1. **Unauthenticated Saree Creation**:
   `{ "id": "saree-1", "name": "Fake Saree", "price": 5000, "image_url": "/img.jpg", "in_stock": true, "category": "Banarasi" }` (with `auth == null`) -> `PERMISSION_DENIED`
2. **Non-Admin Authenticated Saree Creation**:
   `{ "id": "saree-1", "name": "Fake Saree", "price": 5000, "image_url": "/img.jpg", "in_stock": true, "category": "Banarasi" }` (with `auth.uid == 'random-user'`, `email: 'attacker@example.com'`) -> `PERMISSION_DENIED`
3. **Email Spoofing Without Verification**:
   `{ "id": "saree-1", "name": "Spoofed Admin", "price": 8999, "image_url": "/img.jpg", "in_stock": true, "category": "Banarasi" }` (with `auth.token.email == 'preetiharde8b@gmail.com'`, `email_verified == false`) -> `PERMISSION_DENIED`
4. **Shadow Field Injection on Saree Create**:
   `{ "id": "saree-1", "name": "Pure Katan Silk", "price": 8999, "image_url": "/img.jpg", "in_stock": true, "category": "Banarasi", "isFeatured": true }` -> `PERMISSION_DENIED`
5. **Shadow Field Injection on Saree Update**:
   `{ "in_stock": false, "discount": 90 }` -> `PERMISSION_DENIED`
6. **Value Poisoning on Stock Toggle**:
   `{ "in_stock": "yes_in_stock" }` (string instead of boolean) -> `PERMISSION_DENIED`
7. **Negative or Overflow Price Injection**:
   `{ "id": "saree-1", "name": "Pure Katan Silk", "price": -500, "image_url": "/img.jpg", "in_stock": true, "category": "Banarasi" }` -> `PERMISSION_DENIED`
8. **Resource Exhaustion Name Overflow (>120 chars)**:
   `{ "id": "saree-1", "name": "A".repeat(500), "price": 8999, "image_url": "/img.jpg", "in_stock": true, "category": "Banarasi" }` -> `PERMISSION_DENIED`
9. **ID Poisoning / Path Mismatch (`incoming().id != sareeId`)**:
   Document path `/sarees/saree-1` with payload `{ "id": "saree-2", "name": "Pure Katan Silk", "price": 8999, "image_url": "/img.jpg", "in_stock": true, "category": "Banarasi" }` -> `PERMISSION_DENIED`
10. **Immutable ID Mutation on Update**:
    Updating `/sarees/saree-1` with `{ "id": "saree-hijack", "in_stock": false }` -> `PERMISSION_DENIED`
11. **Self-Assigned Admin Privilege Escalation**:
    Non-admin user writing `{ "uid": "attacker-uid", "role": "admin" }` to `/admins/attacker-uid` -> `PERMISSION_DENIED`
12. **Cross-User Admin Document Read**:
    Authenticated user `user-a` attempting `get` on `/admins/user-b` -> `PERMISSION_DENIED`
