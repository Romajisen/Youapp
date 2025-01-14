/*
 Source Server         : mongodb_local
 Source Server Type    : MongoDB
 Source Server Version : 80004 (8.0.4)
 Source Host           : localhost:27017
 Source Schema         : youapp

 Target Server Type    : MongoDB
 Target Server Version : 80004 (8.0.4)
 File Encoding         : 65001
*/


// ----------------------------
// Collection structure for messages
// ----------------------------
db.getCollection("messages").drop();
db.createCollection("messages");

// ----------------------------
// Documents of messages
// ----------------------------
db.getCollection("messages").insert([ {
    _id: ObjectId("6784ed23aea810320e1cfae8"),
    content: "Nuget1234",
    senderId: "6784d1017f3431410e1d090a",
    receiverId: "6784e82faea810320e1cfae1",
    timestamp: ISODate("2025-01-13T10:38:27.001Z"),
    __v: Int32("0")
} ]);

// ----------------------------
// Collection structure for users
// ----------------------------
db.getCollection("users").drop();
db.createCollection("users");

// ----------------------------
// Documents of users
// ----------------------------
db.getCollection("users").insert([ {
    _id: ObjectId("6784d1017f3431410e1d090a"),
    username: "panji",
    password: "$2y$10$edVfUnFTP0v.gOW5FcTLo.yCN.wAnGjNk1O..D1Cju7iyNPfVbJXC",
    horoscope: "Pisces",
    zodiac: "pisces",
    __v: Int32("0")
} ]);
db.getCollection("users").insert([ {
    _id: ObjectId("6784dde9095d5fde02b8a74a"),
    username: "panji.swahastika@yahoo.com",
    password: "$2y$10$Q.xr865K1q9ArBpDP6A2yevBJSDBBnV6G0.1VNGRxdRfdu2lTi0HG",
    horoscope: "string",
    zodiac: "string",
    __v: Int32("0")
} ]);
