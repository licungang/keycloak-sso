import { FieldPath } from "react-hook-form";
import {
  FieldError,
  UserFormFields,
  UserProfileAttributeMetadata,
  UserProfileError,
} from "./userProfileConfig";

export const isBundleKey = (displayName?: string) =>
  displayName?.includes("${");
export const unWrap = (key: string) => key.substring(2, key.length - 1);

export const label = (
  attribute: UserProfileAttributeMetadata,
  t: TranslationFunction,
) =>
  (isBundleKey(attribute.displayName)
    ? t(unWrap(attribute.displayName!))
    : attribute.displayName) || attribute.name;

const ROOT_ATTRIBUTES = ["username", "firstName", "lastName", "email"];

export const isRootAttribute = (attr?: string) =>
  attr && ROOT_ATTRIBUTES.includes(attr);

export const fieldName = (name?: string) =>
  `${
    isRootAttribute(name) ? "" : "attributes."
  }${name}` as FieldPath<UserFormFields>;

export function setUserProfileServerError<T>(
  error: unknown,
  setError: (field: keyof T, params: object) => void,
  t: TranslationFunction,
) {
  (error as FieldError[]).forEach((e) => {
    const params = Object.assign(
      {},
      e.params?.map((p) => t(isBundleKey(p) ? unWrap(p) : p)),
    );
    setError(fieldName(e.field) as keyof T, {
      message: t(e.errorMessage, {
        ...params,
        defaultValue: e.field,
      }),
      type: "server",
    });
  });
}

export function isRequiredAttribute({
  required,
  validators,
}: UserProfileAttributeMetadata): boolean {
  // Check if required is true or if the validators include a validation that would make the attribute implicitly required.
  return required || hasRequiredValidators(validators);
}

/**
 * Checks whether the given validators include a validation that would make the attribute implicitly required.
 */
function hasRequiredValidators(
  validators?: UserProfileAttributeMetadata["validators"],
): boolean {
  // If we don't have any validators, the attribute is not required.
  if (!validators) {
    return false;
  }

  // If the 'length' validator is defined and has a minimal length greater than zero the attribute is implicitly required.
  // We have to do a lot of defensive coding here, because we don't have type information for the validators.
  if (
    "length" in validators &&
    "min" in validators.length &&
    typeof validators.length.min === "number"
  ) {
    return validators.length.min > 0;
  }

  return false;
}

export function isUserProfileError(error: unknown): error is UserProfileError {
  return !!(error as UserProfileError).responseData?.errors;
}

export type TranslationFunction = (key: unknown, params?: object) => string;
