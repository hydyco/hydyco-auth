/**
 * Function - Generate auth token using user object and secret
 * @param {Object} user - User info object
 * @param {string} secretKey - secret key
 * @return {string} token
 */
declare const generateAuthToken: (user: Object, secretOrKey: string) => string;
declare const makeAuth: any;
declare const useAuth: ({ secretOrKey }: {
    secretOrKey: any;
}) => import("express-serve-static-core").Router;
export { useAuth, makeAuth, generateAuthToken };
