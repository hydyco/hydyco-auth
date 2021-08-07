var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
var _this = this;
Object.defineProperty(exports, "__esModule", { value: true });
exports.makeAuth = exports.useAuth = void 0;
var express_1 = require("express");
var passport_1 = __importDefault(require("passport"));
var mongoose_plugin_1 = require("@hydyco/mongoose-plugin");
var core_1 = require("@hydyco/core");
var passport_jwt_1 = require("passport-jwt");
var jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
var fs_1 = __importDefault(require("fs"));
var path_1 = __importDefault(require("path"));
var bcrypt_1 = __importDefault(require("bcrypt"));
var data = __importStar(require("./user.json"));
var router = express_1.Router();
var SALT_WORK_FACTOR = 10;
var file = new core_1.HydycoFile();
if (!fs_1.default.existsSync(path_1.default.join(file.hydycoMappingDir, "user.json")))
    file.writeMappingFile("user", data); // init data
var user = new mongoose_plugin_1.HydycoModel("user");
var userSchema = user.mongooseSchema();
userSchema.pre("save", function (next) {
    var u = this;
    // only hash the password if it has been modified (or is new)
    if (!u.isModified("password"))
        return next();
    // generate a salt
    bcrypt_1.default.genSalt(SALT_WORK_FACTOR, function (err, salt) {
        if (err)
            return next(err);
        // hash the password using our new salt
        bcrypt_1.default.hash(u.password, salt, function (err, hash) {
            if (err)
                return next(err);
            // override the cleartext password with the hashed one
            u.password = hash;
            next();
        });
    });
});
userSchema.methods.comparePassword = function (candidatePassword, cb) {
    var u = this;
    bcrypt_1.default.compare(candidatePassword, u.password, function (err, isMatch) {
        if (err)
            return cb(err);
        cb(null, isMatch);
    });
};
user.setMongooseSchema(userSchema);
var User = user.mongooseModel();
router.use(passport_1.default.initialize());
var makeAuth = passport_1.default.authenticate("jwt", { session: false });
exports.makeAuth = makeAuth;
var useAuth = function (_a) {
    var secretOrKey = _a.secretOrKey;
    var jwtOptions = {
        jwtFromRequest: function (req) {
            var token = null;
            if (req && req.headers && req.headers["authorization"]) {
                token = req.headers["authorization"];
            }
            return token;
        },
        secretOrKey: secretOrKey,
    };
    //JWT strategy options for passport (jwt middleware to verify & sign user)
    passport_1.default.use(new passport_jwt_1.Strategy(jwtOptions, function (token, done) { return __awaiter(_this, void 0, void 0, function () {
        var user_1;
        return __generator(this, function (_a) {
            if (!token)
                return [2 /*return*/, done(null, true)];
            try {
                user_1 = JSON.parse(token.aud);
                return [2 /*return*/, done(null, user_1)];
            }
            catch (e) {
                return [2 /*return*/, done(null, false)];
            }
            return [2 /*return*/];
        });
    }); }));
    function generateAccessToken(user) {
        var options = {
            expiresIn: "1y",
            audience: JSON.stringify(user),
        };
        return jsonwebtoken_1.default.sign({}, secretOrKey, options);
    }
    router.post("/auth/login", function (request, response) { return __awaiter(_this, void 0, void 0, function () {
        var _a, email, password, user_2, token, error_1;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    _a = request.body, email = _a.email, password = _a.password;
                    _b.label = 1;
                case 1:
                    _b.trys.push([1, 3, , 4]);
                    return [4 /*yield*/, User.findOne({ email: email })];
                case 2:
                    user_2 = _b.sent();
                    if (!user_2)
                        return [2 /*return*/, response
                                .send({ status: false, message: "User not found" })
                                .status(404)];
                    user_2.comparePassword(password, function (err, isMatch) {
                        if (err)
                            return response
                                .send({ status: false, message: "Password does not match" })
                                .status(404);
                    });
                    token = generateAccessToken(user_2);
                    return [2 /*return*/, response.send({ status: true, message: "User authorized", token: token })];
                case 3:
                    error_1 = _b.sent();
                    return [2 /*return*/, response
                            .send({ status: false, message: error_1.message })
                            .status(500)];
                case 4: return [2 /*return*/];
            }
        });
    }); });
    return router;
};
exports.useAuth = useAuth;
//# sourceMappingURL=index.js.map