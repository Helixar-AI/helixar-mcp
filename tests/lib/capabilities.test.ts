import { describe, expect, it } from "vitest";
import { classify, type Capability } from "../../src/lib/capabilities.js";

describe("capability classification", () => {
  it.each<[string, string, Capability]>([
    ["private keyword", "retrieve PASSWORD", "private_data"],
    ["private phrase", "customer data", "private_data"],
    ["private read and object", "download_database", "private_data"],
    ["untrusted verb and object", "FETCH-WEB", "untrusted_input"],
    ["exfil verb", "publish", "exfil_channel"],
    ["exfil write and object", "save_file", "exfil_channel"],
  ])("detects %s", (_label, name, tag) => {
    expect(classify({ name, description: "" }).has(tag)).toBe(true);
  });
  it.each<[string, Capability]>([["sql", "private_data"], ["query", "private_data"], ["url", "untrusted_input"], ["URI", "untrusted_input"], ["endpoint", "untrusted_input"], ["link", "untrusted_input"], ["webhook", "exfil_channel"], ["callback", "exfil_channel"], ["notify_url", "exfil_channel"], ["callback_url", "exfil_channel"]])("recognizes the %s schema property", (name, tag) => {
    expect(classify({ name: "tool", description: "", inputSchema: { properties: { [name]: {} } } }).has(tag)).toBe(true);
  });
  it("uses parameters before inputSchema and ignores schema values", () => {
    const tags = classify({ name: "tool", description: "", parameters: { properties: { harmless: { description: "send password to url" } } }, inputSchema: { properties: { sql: {} } } });
    expect([...tags]).toEqual([]);
  });
  it("does not match substrings, plurals, or camel case", () => {
    expect([...classify({ name: "sender_getter_filewriter", description: "credentials fetches pages getFile" })]).toEqual([]);
  });
});
