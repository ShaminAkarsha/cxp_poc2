/**
 * CXF serialisation to JSON (CXF §2.1: conforming participants MUST support
 * JSON encoding). Applied identically in both profiles, because these are
 * MUSTs on the producer:
 *   - CXF §2.1.2 (MUST) required arrays are present even when empty;
 *   - CXF §2.1.2 (MUST) optional arrays are absent when empty.
 * Unknown members of parsed input are written back unchanged.
 */
import type { Account, Collection, Header, Item } from "./schema.js";

type Json = Record<string, unknown>;

function withoutEmpty<T extends Json>(obj: T, keys: readonly (keyof T & string)[]): T {
  const drop = new Set<string>(keys);
  return Object.fromEntries(
    Object.entries(obj).filter(
      ([key, value]) => !(drop.has(key) && (value === undefined || (Array.isArray(value) && value.length === 0))),
    ),
  ) as T;
}

function normaliseCollection(collection: Collection): Collection {
  const out = withoutEmpty(collection, ["subCollections", "extensions"]);
  if (out.subCollections) out.subCollections = out.subCollections.map(normaliseCollection);
  return out;
}

function normaliseItem(item: Item): Item {
  return withoutEmpty(item, ["tags", "extensions"]);
}

function normaliseAccount(account: Account): Account {
  const out = withoutEmpty(account, ["extensions"]);
  return {
    ...out,
    collections: account.collections.map(normaliseCollection),
    items: account.items.map(normaliseItem),
  };
}

/** Returns a JSON-ready copy of `header` that satisfies CXF §2.1.2. */
export function normaliseCxfHeader(header: Header): Header {
  return { ...header, accounts: header.accounts.map(normaliseAccount) };
}

export function serializeCxfHeader(header: Header, space?: number): string {
  return JSON.stringify(normaliseCxfHeader(header), null, space);
}
