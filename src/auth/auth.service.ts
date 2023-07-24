import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as bcrypt from 'bcrypt';
import { JwtPayload, Tokens } from './types';
import { JwtService } from '@nestjs/jwt';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwtService: JwtService) {}

  async signupLocal(dto: AuthDto): Promise<Tokens> {
    const hash = await this.hashData(dto.password);
    try {
      const newUser = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

      // calling function and generate tokens
      const tokens = await this.getTokens(newUser.id, newUser.email);
      // calling funtion to update hashedRt in database of user
      await this.updateRtHash(newUser.id, tokens.refresh_token);

      return tokens;
    } catch (error) {
      // check if error is from prisma
      if (error instanceof PrismaClientKnownRequestError) {
        // if the error code P2002, which is code from prisma
        // for this case its email, that have been set unique
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }
      throw error;
    }
  }

  async signinLocal(dto: AuthDto): Promise<Tokens> {
    const user = await this.prisma.user.findFirst({
      where: {
        email: dto.email,
      },
    });

    if (!user) throw new ForbiddenException('Access denied');

    const passwordMatcher = await bcrypt.compare(dto.password, user.hash);

    if (!passwordMatcher) throw new ForbiddenException('Access denied');

    // calling function and generate tokens
    const tokens = await this.getTokens(user.id, user.email);
    // calling funtion to update hashedRt in database of user
    await this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;
  }

  async logout(userId: number) {
    // Find user by userId and check if the hasedRt not null, if the user found, set hasredRt to null
    await this.prisma.user.update({
      where: {
        id: userId,
        hashedRt: {
          not: null,
        },
      },
      data: {
        hashedRt: null,
      },
    });
  }

  async refreshToken(userId: number, rt: string) {
    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
    });

    if (!user || !user.hashedRt) throw new ForbiddenException('Access denied');

    const rtMatcher = bcrypt.compare(rt, user.hashedRt);

    if (!rtMatcher) throw new ForbiddenException('Access Denied');

    // calling function and generate tokens
    const tokens = await this.getTokens(user.id, user.email);
    // calling funtion to update hashedRt in database of user
    await this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;
  }

  //   Function to update hashedRt on user in database
  async updateRtHash(userId: number, rt: string) {
    const hash = await this.hashData(rt);
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRt: hash,
      },
    });
  }

  //   Function to hash using bcrypt
  hashData(data: string) {
    return bcrypt.hash(data, 10);
  }

  //   Function to generate access token and refresh token that return promise of tokens
  async getTokens(userId: number, email: string): Promise<Tokens> {
    const jwtPayload: JwtPayload = {
      id: userId,
      email: email,
    };

    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(jwtPayload, {
        secret: 'at-secret',
        expiresIn: '15m',
      }),
      this.jwtService.signAsync(jwtPayload, {
        secret: 'rt-secret',
        expiresIn: '7d',
      }),
    ]);

    return {
      access_token: at,
      refresh_token: rt,
    };
  }
}
