import { Ajv2020, type ErrorObject } from "ajv/dist/2020.js";
import { readFileSync } from "node:fs";
import { isIP } from "node:net";
import { VATE_A2A_EXTENSION_URI, type A2aLikeObject } from "./types.js";

const schemaUrl = new URL(
  "../../../schemas/a2a-vate-metadata.schema.json",
  import.meta.url
);
const schema = JSON.parse(readFileSync(schemaUrl, "utf8"));
const ajv = new Ajv2020({
  allErrors: true,
  strict: false,
  validateFormats: true,
});

const rfc3339DateTimePattern =
  /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d{1,6})?(?:[Zz]|([+-])(\d{2}):(\d{2}))(?![\s\S])/;

function isLeapYear(year: number): boolean {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

function isRfc3339DateTime(value: string): boolean {
  const match = rfc3339DateTimePattern.exec(value);
  if (!match) {
    return false;
  }

  const yearText = match[1];
  const monthText = match[2];
  const dayText = match[3];
  const hourText = match[4];
  const minuteText = match[5];
  const secondText = match[6];
  const offsetHourText = match[8];
  const offsetMinuteText = match[9];
  if (
    !yearText ||
    !monthText ||
    !dayText ||
    !hourText ||
    !minuteText ||
    !secondText
  ) {
    return false;
  }

  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const daysByMonth = [
    31,
    isLeapYear(year) ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ];
  const daysInMonth = daysByMonth[month - 1];
  if (
    year < 1 ||
    month < 1 ||
    month > 12 ||
    !daysInMonth ||
    day < 1 ||
    day > daysInMonth ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  ) {
    return false;
  }

  if (offsetHourText && Number(offsetHourText) > 23) {
    return false;
  }
  if (offsetMinuteText && Number(offsetMinuteText) > 59) {
    return false;
  }
  return true;
}

function isAbsoluteUri(value: string): boolean {
  // RFC 3986 generic URI syntax, without WHATWG URL repair/normalization.
  // Scheme-specific resolution and authority are separate from this format check.
  if (/[^\x21-\x7e]/.test(value) || /%(?![0-9A-Fa-f]{2})/.test(value)) {
    return false;
  }
  const parts = /^[A-Za-z][A-Za-z0-9+.-]*:([^?#]*)(?:\?([^#]*))?(?:#([^#]*))?(?![\s\S])/.exec(value);
  if (!parts) {
    return false;
  }
  const queryOrFragment = /^[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*(?![\s\S])/;
  if (![parts[2], parts[3]].every((part) => part === undefined || queryOrFragment.test(part))) {
    return false;
  }
  let path = parts[1] ?? "";
  if (path.startsWith("//")) {
    const end = path.indexOf("/", 2);
    const authority = end < 0 ? path.slice(2) : path.slice(2, end);
    path = end < 0 ? "" : path.slice(end);
    const at = authority.indexOf("@");
    const hostPort = at < 0 ? authority : authority.slice(at + 1);
    if (at >= 0 && !/^[A-Za-z0-9._~!$&'()*+,;=:%-]*(?![\s\S])/.test(authority.slice(0, at))) {
      return false;
    }
    if (hostPort.startsWith("[")) {
      const host = /^\[([^\]]+)\](?::[0-9]*)?(?![\s\S])/.exec(hostPort)?.[1];
      if (!host || host.includes("%") || !(
        isIP(host) === 6 || /^[vV][0-9A-Fa-f]+\.[A-Za-z0-9._~!$&'()*+,;=:-]+(?![\s\S])/.test(host)
      )) {
        return false;
      }
    } else if (!/^[A-Za-z0-9._~!$&'()*+,;=%-]*(?::[0-9]*)?(?![\s\S])/.test(hostPort)) {
      return false;
    }
  }
  return /^[A-Za-z0-9._~!$&'()*+,;=:@%/-]*(?![\s\S])/.test(path);
}

ajv.addFormat("date-time", {
  type: "string",
  validate: isRfc3339DateTime,
});
ajv.addFormat("uri", {
  type: "string",
  validate: isAbsoluteUri,
});
const validate = ajv.compile(schema);

export function extractVateMetadata(
  value: A2aLikeObject,
  extensionUri = VATE_A2A_EXTENSION_URI
): unknown | undefined {
  return value.metadata?.[extensionUri];
}

export function validateVateA2aMetadata(value: unknown): string[] {
  if (validate(value)) {
    return [];
  }
  return (validate.errors ?? []).map((error: ErrorObject) => {
    const path = error.instancePath || "/";
    return `${path} ${error.message ?? "failed validation"}`;
  });
}
