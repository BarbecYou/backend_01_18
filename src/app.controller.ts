import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  Redirect,
  Render,
  Session,
} from '@nestjs/common';
import { AppService } from './app.service';
import db from './db';
import * as bcrypt from 'bcrypt';
import UserDataDto from './userdata.dto';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  @Render('index')
  async index(@Session() session: Record<string, any>) {
    let userName = '';
    if (session.user_id) {
      const [rows]: any = await db.execute(
        'SELECT username FROM users WHERE id = ?',
        [session.user_id],
      );
      userName = rows[0].username;
    } else {
      userName = 'Guest';
    }

    return { message: 'Welcome to the homepage, ' + userName };
  }

  @Get('/register')
  @Render('register')
  registerForm() {
    return {};
  }

  @Post('/register')
  @Redirect()
  async register(@Body() userdata: UserDataDto) {
    await db.execute('INSERT INTO users (username, password) VALUES (?, ?)', [
      userdata.username,
      await bcrypt.hash(userdata.password, 10),
    ]);
    return {
      url: '/',
    };
  }

  @Get('/login')
  @Render('login')
  loginForm() {
    return {};
  }

  @Post('/login')
  @Redirect()
  async login(
    @Body() userdata: UserDataDto,
    @Session() session: Record<string, any>,
  ) {
    const [rows]: any = await db.execute(
      'SELECT id, username, password FROM users WHERE username = ?',
      [userdata.username],
    );
    if (rows.length == 0) {
      return { url: '/login' };
    }
    if (await bcrypt.compare(userdata.password, rows[0].password)) {
      session.user_id = rows[0].id;
      return { url: '/' };
    } else {
      return { url: '/login' };
    }
  }

  @Get('/logout')
  @Redirect()
  logout(@Session() session: Record<string, any>) {
    session.user_id = null;
    return { url: '/' };
  }

  @Get('users')
  async allUsers() {
    const [users] = await db.execute(
      'SELECT id, username FROM users ORDER BY username',
    );
    return { users };
  }

  @Post('api/register')
  async registerAPI(@Body() userdata: UserDataDto) {
    await db.execute('INSERT INTO users (username, password) VALUES (?, ?)', [
      userdata.username,
      await bcrypt.hash(userdata.password, 10),
    ]);
  }

  @Get('api/users/:id')
  async getUserData(@Param('id') id: number) {
    const [user] = await db.execute('select * from users where id = ?', [id]);
    return user[0];
  }

  @Delete('api/users/:id')
  async deleteUserById(@Param('id') id: number) {
    await db.execute('delete from users where id = ?', [id]);
  }

  @Patch('api/users/:id')
  async updateUser(@Param('id') id: number, @Body() body: UserDataDto) {
    const [ users ] = await db.execute(
      'select username, password from users where id = ?',
      [id],
    );
    const currentUser = users[0] as UserDataDto;
    if (body.username) {
      currentUser.username = body.username;
    }
    if (body.password) {
      currentUser.password = body.password;
    }

    db.execute('update users set username = ?, password = ? where id = ?', [
      currentUser.username,
      currentUser.password,
      id,
    ]);
  }
}
