declare const makeAuth: any;
declare const useAuth: ({ secretOrKey }: {
    secretOrKey: any;
}) => import("express-serve-static-core").Router;
export { useAuth, makeAuth };
