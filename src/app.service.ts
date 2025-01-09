import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  getHello(obj): any {
    return obj;
  }
}
