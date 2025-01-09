import { BadRequestException, Injectable, InternalServerErrorException, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { SignupDto } from './dtos/singup.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schemas/user.schema';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt'
import { SigninDto } from './dtos/singin.dto';
import { JwtService } from '@nestjs/jwt';
import { RefreshToken } from './schemas/refresh-token.schema';
import { v4 as uuidv4 } from 'uuid'
import { ResetToken } from './schemas/reset-token.schema';
import { nanoid } from 'nanoid';
import { MailService } from 'src/services/mail.services';

@Injectable()
export class AuthService {


    constructor(
        @InjectModel(User.name) private UserModel: Model<User>,
        @InjectModel(RefreshToken.name) private RefreshTokenModel: Model<RefreshToken>,
        @InjectModel(ResetToken.name) private ResetTokenModel: Model<ResetToken>,
        private jwtService: JwtService,
        private mailService: MailService

    ) { }

    async signup(signupData: SignupDto) {
        const { name, email, password } = signupData
        //check email is already exist
        const emailExist = await this.UserModel.findOne({
            email: email
        })

        if (emailExist) {
            throw new BadRequestException('Email already exist')
        }

        // hash password
        const hashedPassword = await bcrypt.hash(password, 10)

        //create user document and save in db
        await this.UserModel.create({
            name,
            email,
            password: hashedPassword
        })
    }


    //signin
    async signin(signinData: SigninDto) {
        const { email, password } = signinData
        // user exist
        const user = await this.UserModel.findOne({
            email
        })

        if (!user) {
            throw new UnauthorizedException('Wrong credentials')
        }


        //check password
        const passwordMatched = await bcrypt.compare(password, user.password)

        if (!passwordMatched) {
            throw new UnauthorizedException('Wrong credentials')
        }

        //generate token

        const tokens = await this.generateUserToken(user._id)

        return {
            ...tokens,
            userId: user._id
        }

    }


    //change password
    async changePassword(userId: string, oldPassword: string, newPassword: string) {
        //find user is valid
        const user = await this.UserModel.findById(userId)
        if (!user) {
            throw new NotFoundException("User Not Found")
        }

        //compare old password with DB password
        const passwordMatched = await bcrypt.compare(oldPassword, user.password)

        if (!passwordMatched) {
            throw new UnauthorizedException('Wrong credentials')
        }

        //change user password with hashing
        const newHashedPassword = await bcrypt.hash(newPassword, 10)
        user.password = newHashedPassword
        await user.save()
    }


    //forgot password
    async forgotPassword(email: string) {
        //check that user is exist
        const user = await this.UserModel.findOne({
            email
        })

        if (user) {

            //if user exist generate reset link
            const expiryDate = new Date();
            expiryDate.setHours(expiryDate.getHours() + 1)
            const resetToken = nanoid(64)

            await this.ResetTokenModel.create({
                token: resetToken,
                userId: user._id,
                expiryDate
            })

            // send reset link to user by email
            this.mailService.sendPasswordResetEmail(email, resetToken)
        }

        return {
            message: "If user exists then they will recive an email"
        }

    }

    //reset password
    async resetPassword(newPassword: string, resetToken: string) {

        //find valid reset token on db
        const token = await this.ResetTokenModel.findOneAndDelete({
            token: resetToken,
            expiryDate: {
                $gte: new Date()
            }
        })

        if (!token) {
            throw new UnauthorizedException('Invalid link')
        }

        //change user password with hashed
        const user = await this.UserModel.findById(token.userId)
        if (!user) {
            throw new InternalServerErrorException()
        }

        user.password = await bcrypt.hash(newPassword, 10)
        await user.save()
    }

    //token rotation
    async refreshToken(refreshToken: string) {
        const token = await this.RefreshTokenModel.findOne({
            token: refreshToken,
            expiryDate: {
                $gte: new Date()
            }
        })

        if (!token) {
            throw new UnauthorizedException("Refresh token invalid")
        }

        return this.generateUserToken(token.userId)
    }


    // generate tokens
    async generateUserToken(userId) {

        const accessToken = this.jwtService.sign({ userId }, { expiresIn: '1h' })

        const refreshToken = uuidv4()

        await this.storeRefreshToken(refreshToken, userId)
        return {
            accessToken,
            refreshToken
        }
    }

    // store refresh token
    async storeRefreshToken(token: string, userId) {

        //calculate expiry date 3 days from now
        const expiryDate = new Date();
        expiryDate.setDate(expiryDate.getDate() + 3)

        await this.RefreshTokenModel.updateOne(
            {
                userId
            },
            {
                $set: {
                    expiryDate,
                    token
                }
            },
            {
                upsert: true
            }
        )
    }






}
