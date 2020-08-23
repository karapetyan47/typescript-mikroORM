import { Resolver, Mutation, InputType, Field, Arg, Ctx, ObjectType, Query } from "type-graphql";
import { MyContext } from "../types";
import { User } from "../entities/User";
import argon2 from "argon2";
import { EntityManager } from "@mikro-orm/postgresql"

@InputType()
class UsernamePasswordInput {
    @Field()
    username: string
    @Field()
    password: string
}

@ObjectType()
class FieldError {
    @Field()
    field: string
    @Field()
    message: string
}


@ObjectType()
class UserResponse {
    @Field(() => [FieldError], { nullable: true })
    error?: FieldError[]

    @Field(() => User, { nullable: true })
    user?: User
}

@Resolver()
export class UserResolver {
    @Query(() => User)
    async me(
        @Ctx() { em, req }: MyContext
    ) {
        if (!req.session.userId) {
            return null
        }

        const user = em.findOne(User, { id: req.session.userId })
        return user
    }



    @Mutation(() => UserResponse)
    async register(
        @Arg("options") options: UsernamePasswordInput,
        @Ctx() { em, req }: MyContext
    ): Promise<UserResponse> {

        if (options.username.length <= 2) {
            return {
                error: [
                    {
                        field: "username",
                        message: "length must be greater than 2"
                    }
                ]
            }
        }

        if (options.password.length <= 3) {
            return {
                error: [
                    {
                        field: "username",
                        message: "length must be greater than 3"
                    }
                ]
            }
        }

        const hasshedPassword = await argon2.hash(options.password)
        let user;
        try {
            const result = await (em as EntityManager)
                .createQueryBuilder(User)
                .getKnexQuery()
                .insert({
                    username: options.username,
                    password: hasshedPassword,
                    created_at: new Date(),
                    updated_at: new Date()
                })
                .returning("*")
            user = result[0]
        } catch (err) {
            if (err.code === "23505") {
                return {
                    error: [
                        {
                            field: "username",
                            message: "username already taken"
                        }
                    ]
                }
            }
        }
        req.session.userId = user.id

        return { user }
    }

    @Mutation(() => UserResponse)
    async login(
        @Arg("options") options: UsernamePasswordInput,
        @Ctx() { em, req }: MyContext
    ): Promise<UserResponse> {

        if (options.username.length <= 2) {
            return {
                error: [
                    {
                        field: "username",
                        message: "length must be greater than 2"
                    }
                ]
            }
        }

        if (options.password.length <= 3) {
            return {
                error: [
                    {
                        field: "username",
                        message: "length must be greater than 3"
                    }
                ]
            }
        }
        const user = await em.findOne(User, { username: options.username })


        if (!user) {
            return {
                error: [{
                    field: "username",
                    message: "that username does not exist"
                }]
            }
        }
        const valid = await argon2.verify(user.password, options.password)

        if (!valid) {
            return {
                error: [{
                    field: "password",
                    message: "incorrect password"
                }]
            }
        }

        req.session.userId = user.id

        return { user }
    }

}