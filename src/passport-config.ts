import passportlocal from 'passport-local';
import passport, { PassportStatic } from 'passport';
import bcrypt from 'bcrypt'

const LocalStrategy = passportlocal.Strategy


export function initialize(passport: PassportStatic, getUserByEmail: any, getUserById: any) {
    const authenticateUser = async (email: string, password: string, done: any) => {
        const user = getUserByEmail(email)
        if (user == null) {
            return done(null, false, { message: 'No user with that email' })
        }

        try {
            if (await bcrypt.compare(password, user.password)) {
                return done(null, user)
            } else {
                return done(null, false, { message: 'Password incorrect' })
            }
        } catch (e) {
            return done(e)
        }
    }

    passport.use(new LocalStrategy({ usernameField: 'email' }, authenticateUser))
    passport.serializeUser((user: any, done: any) => done(null, user.id))
    passport.deserializeUser((id: any, done: any) => {
        return done(null, getUserById(id))
    })
}

