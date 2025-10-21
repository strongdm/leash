import { faker } from "@faker-js/faker";

export function pick<T>(arr: readonly T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

export function id(prefix = "id"): string {
  return `${prefix}-${faker.string.alphanumeric(8).toLowerCase()}`;
}

export function now(): number {
  return Date.now();
}

