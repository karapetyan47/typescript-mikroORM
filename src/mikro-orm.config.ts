import { Post } from "./entities/Post";
import { __prod__ } from "./constants";
import { MikroORM } from "@mikro-orm/core";
import path from "path"
import { User } from "./entities/User";

export default {
    entities: [Post,User],
    migrations: {
        path: path.join(__dirname, "./migrations"),
        pattern: /^[\w-]+\d+\.[tj]s$/,
    },
    dbName: "lireddit",
    password: "postgres",
    type: "postgresql",
    debug: !__prod__
} as Parameters<typeof MikroORM.init>[0]
