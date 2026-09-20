import { APP_INFO } from "./version";

export function getVersionFromPackage() {
  return { version: APP_INFO.version };
}
