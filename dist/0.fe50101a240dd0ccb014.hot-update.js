"use strict";
exports.id = 0;
exports.ids = null;
exports.modules = {

/***/ 12:
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserService = void 0;
const common_1 = __webpack_require__(6);
const mongoose_1 = __webpack_require__(7);
const mongoose_2 = __webpack_require__(13);
const user_schema_1 = __webpack_require__(14);
const bcrypt = __webpack_require__(15);
const jwt_1 = __webpack_require__(9);
let UserService = class UserService {
    constructor(userModel, jwtService) {
        this.userModel = userModel;
        this.jwtService = jwtService;
    }
    async create(createUserDto) {
        const createdUser = new this.userModel(createUserDto);
        return createdUser.save();
    }
    async findOne(username) {
        return this.userModel.findOne({ username }).exec();
    }
    async update(username, updateUserDto) {
        return this.userModel.findOneAndUpdate({ username }, updateUserDto, { new: true }).exec();
    }
    async getProfile(username) {
        const user = await this.findOne(username);
        if (!user) {
            throw new common_1.NotFoundException('User not found');
        }
        return user;
    }
    async login(loginDto) {
        const user = await this.findOne(loginDto.username);
        console.log(user);
        if (!user || !(await bcrypt.compare(loginDto.password, user.password))) {
            throw new common_1.NotFoundException('Invalid credentials');
        }
        const payload = { username: user.username, sub: user._id };
        return {
            access_token: this.jwtService.sign(payload),
        };
    }
};
UserService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, mongoose_1.InjectModel)(user_schema_1.User.name)),
    __metadata("design:paramtypes", [typeof (_a = typeof mongoose_2.Model !== "undefined" && mongoose_2.Model) === "function" ? _a : Object, typeof (_b = typeof jwt_1.JwtService !== "undefined" && jwt_1.JwtService) === "function" ? _b : Object])
], UserService);
exports.UserService = UserService;


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("506b145237f2eb105bbb")
/******/ })();
/******/ 
/******/ }
;