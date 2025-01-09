import { CanActivate, ExecutionContext, Injectable, Logger, UnauthorizedException } from "@nestjs/common";
import { Observable } from "rxjs";
import { JwtService } from '@nestjs/jwt';
import { Request } from "express";


@Injectable()
export class AuthGuard implements CanActivate {

    constructor(private jwtService: JwtService) { }


    canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
        const request = context.switchToHttp().getRequest()
        const token = this.extractTokenFromHeader(request)

        if (!token) {
            // return false  // Access Forbidden 403
            throw new UnauthorizedException('Invaid token')
        }

        try {
            const payload = this.jwtService.verify(token)
            request.userId = payload.userId
        } catch (error) {
            Logger.error(error.message)
            throw new UnauthorizedException('Invaid token')
        }
        return true

    }

    private extractTokenFromHeader(request: Request): string | undefined {
        return request.headers.authorization?.split(' ')[1]
    }
}