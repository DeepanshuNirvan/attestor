/**
 * Reading text out of a FormData.
 *
 * `FormData.get` returns a string or a File, and stringifying a File silently produces
 * "[object File]". Anything that reaches the API should have been a string or nothing at all, so
 * this returns the empty string rather than a coerced object.
 */
export function formText(form: FormData, name: string, fallback = ''): string {
  const value = form.get(name);
  return typeof value === 'string' && value !== '' ? value : fallback;
}
