/**
 * Firestore Security Rules Test Suite for Swapari Saree
 * Verifies all 12 "Dirty Dozen" adversarial payloads return PERMISSION_DENIED.
 */

export interface DirtyDozenTestCase {
  id: number;
  name: string;
  operation: 'create' | 'update' | 'get' | 'delete';
  path: string;
  auth: {
    uid: string;
    email?: string;
    email_verified?: boolean;
  } | null;
  payload?: Record<string, unknown>;
  expectedResult: 'PERMISSION_DENIED';
}

export const DIRTY_DOZEN_TESTS: DirtyDozenTestCase[] = [
  {
    id: 1,
    name: 'Unauthenticated Saree Creation',
    operation: 'create',
    path: '/sarees/saree-1',
    auth: null,
    payload: {
      id: 'saree-1',
      name: 'Pure Katan Silk Banarasi',
      price: 8999,
      image_url: '/src/assets/images/saree.jpg',
      in_stock: true,
      category: 'Banarasi',
    },
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 2,
    name: 'Non-Admin Authenticated Saree Creation',
    operation: 'create',
    path: '/sarees/saree-1',
    auth: { uid: 'user-123', email: 'shopper@example.com', email_verified: true },
    payload: {
      id: 'saree-1',
      name: 'Pure Katan Silk Banarasi',
      price: 8999,
      image_url: '/src/assets/images/saree.jpg',
      in_stock: true,
      category: 'Banarasi',
    },
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 3,
    name: 'Email Spoofing Without Verification',
    operation: 'create',
    path: '/sarees/saree-1',
    auth: { uid: 'spoof-uid', email: 'sujeetharde5@gmail.com', email_verified: false },
    payload: {
      id: 'saree-1',
      name: 'Pure Katan Silk Banarasi',
      price: 8999,
      image_url: '/src/assets/images/saree.jpg',
      in_stock: true,
      category: 'Banarasi',
    },
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 4,
    name: 'Shadow Field Injection on Saree Create',
    operation: 'create',
    path: '/sarees/saree-1',
    auth: { uid: 'admin-uid', email: 'sujeetharde5@gmail.com', email_verified: true },
    payload: {
      id: 'saree-1',
      name: 'Pure Katan Silk Banarasi',
      price: 8999,
      image_url: '/src/assets/images/saree.jpg',
      in_stock: true,
      category: 'Banarasi',
      shadowAdminFlag: true,
    },
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 5,
    name: 'Shadow Field Injection on Saree Update',
    operation: 'update',
    path: '/sarees/saree-1',
    auth: { uid: 'admin-uid', email: 'sujeetharde5@gmail.com', email_verified: true },
    payload: {
      id: 'saree-1',
      name: 'Pure Katan Silk Banarasi',
      price: 8999,
      image_url: '/src/assets/images/saree.jpg',
      in_stock: false,
      category: 'Banarasi',
      extraField: 'injected',
    },
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 6,
    name: 'Value Poisoning on Stock Toggle',
    operation: 'update',
    path: '/sarees/saree-1',
    auth: { uid: 'admin-uid', email: 'sujeetharde5@gmail.com', email_verified: true },
    payload: {
      id: 'saree-1',
      name: 'Pure Katan Silk Banarasi',
      price: 8999,
      image_url: '/src/assets/images/saree.jpg',
      in_stock: 'true',
      category: 'Banarasi',
    },
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 7,
    name: 'Negative Price Injection',
    operation: 'create',
    path: '/sarees/saree-1',
    auth: { uid: 'admin-uid', email: 'sujeetharde5@gmail.com', email_verified: true },
    payload: {
      id: 'saree-1',
      name: 'Pure Katan Silk Banarasi',
      price: -100,
      image_url: '/src/assets/images/saree.jpg',
      in_stock: true,
      category: 'Banarasi',
    },
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 8,
    name: 'Resource Exhaustion Name Overflow (>120 chars)',
    operation: 'create',
    path: '/sarees/saree-1',
    auth: { uid: 'admin-uid', email: 'sujeetharde5@gmail.com', email_verified: true },
    payload: {
      id: 'saree-1',
      name: 'A'.repeat(250),
      price: 8999,
      image_url: '/src/assets/images/saree.jpg',
      in_stock: true,
      category: 'Banarasi',
    },
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 9,
    name: 'ID Poisoning / Path Mismatch',
    operation: 'create',
    path: '/sarees/saree-1',
    auth: { uid: 'admin-uid', email: 'sujeetharde5@gmail.com', email_verified: true },
    payload: {
      id: 'saree-different-id',
      name: 'Pure Katan Silk Banarasi',
      price: 8999,
      image_url: '/src/assets/images/saree.jpg',
      in_stock: true,
      category: 'Banarasi',
    },
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 10,
    name: 'Immutable ID Mutation on Update',
    operation: 'update',
    path: '/sarees/saree-1',
    auth: { uid: 'admin-uid', email: 'sujeetharde5@gmail.com', email_verified: true },
    payload: {
      id: 'saree-hijacked',
      name: 'Pure Katan Silk Banarasi',
      price: 8999,
      image_url: '/src/assets/images/saree.jpg',
      in_stock: false,
      category: 'Banarasi',
    },
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 11,
    name: 'Self-Assigned Admin Privilege Escalation',
    operation: 'create',
    path: '/admins/attacker-uid',
    auth: { uid: 'attacker-uid', email: 'attacker@example.com', email_verified: true },
    payload: {
      uid: 'attacker-uid',
      role: 'admin',
    },
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 12,
    name: 'Cross-User Admin Document Read',
    operation: 'get',
    path: '/admins/other-admin-uid',
    auth: { uid: 'regular-user-uid', email: 'user@example.com', email_verified: true },
    expectedResult: 'PERMISSION_DENIED',
  },
];
