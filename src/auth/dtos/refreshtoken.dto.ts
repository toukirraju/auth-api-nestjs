import { IsEmail, IsString, Matches, MinLength } from "class-validator";

export class RefreshTokenDto {

    @IsString()
    refreshToken: string;

}