import { Body, Controller, Post, Put, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dtos/singup.dto';
import { SigninDto } from './dtos/singin.dto';
import { RefreshTokenDto } from './dtos/refreshtoken.dto';
import { ChangePasswordDto } from './dtos/changePassword.dto';
import { AuthGuard } from 'src/guards/auth.guard';
import { ForgotPasswordDto } from './dtos/forgotPassword.dto';
import { ResetPasswordDto } from './dtos/resetPassword.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) { }



  //signup
  @Post('signup')
  async signUp(@Body() signupData: SignupDto) {
    return this.authService.signup(signupData)
  }

  //signin
  @Post('signin')
  async signIn(@Body() signinData: SigninDto) {
    return this.authService.signin(signinData)
  }

  //refresh token
  @Post('refresh')
  async refreshToken(@Body() refreshtokenData: RefreshTokenDto) {
    return this.authService.refreshToken(refreshtokenData.refreshToken)
  }


  //change password
  @UseGuards(AuthGuard)
  @Put('change-password')
  async changePassword(@Body() changePasswordData: ChangePasswordDto, @Req() req) {
    return this.authService.changePassword(
      req.userId,
      changePasswordData.oldPassword,
      changePasswordData.newPassword)
  }


  //forgot password
  @Post('forgot-password')
  async forgotPassword(@Body() forgotPasswordData: ForgotPasswordDto) {
    return this.authService.forgotPassword(forgotPasswordData.email)
  }

  //reset password
  @Put('reset-password')
  async resetPassword(@Body() resetPasswordData: ResetPasswordDto) {
    return this.authService.resetPassword(
      resetPasswordData.newPassword,
      resetPasswordData.resetToken)
  }




}
