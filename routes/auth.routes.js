const {Router} = require("express")
const bcrypt = require("bcryptjs")
const config = require("config")
const jwt = require("jsonwebtoken")
const {check, validationResult }=require("express-validator")
const router = Router()
const User = require("../models/User")



//Эндпоинт 1
//api/auth/register
router.post(
    "/register",
    //проводим валидацию
    [
check("email", "Некорректный email").isEmail(),
check("password", "Минимальная длинна пароля 6 символов")
.isLength({min:6})
    ],
     async (req,res)=>{
try{
   
    //продолжаем валидацию
    const errors = validationResult(req)
    //если объект не пустой(есть какие-то ошибки), тогда я сразу же верну их на фронтенд
if(!errors.isEmpty()){
    return res.status(400).json({
       errors: errors.array(),
       message:"Некорректные данные при регистрации"
    })
}
//Получаем мэил и пороль от пользователя
    const {email, password}=req.body
//Проверка пользователя в базе данных(зарегестрированный ли он)
const candidate = await User.findOne({email:email})
if(candidate){
   return res.status(400).json({message:"Такой пользователь уже существует"})
}
//Хешируем пароль
const hashedPassword = await bcrypt.hash(password,12)
//Создаем нового пользователя
const user = new User({email:email, password:hashedPassword})
//Ждем пока пользователь сохраниться
await user.save()
//Отвечаем фронтенду, что он зарегистрировался
res.status(201).json({message:"Пользователь создан"})
}catch(e){
    res.status(500).json({message:"Что-то пошло не так, попробуйте снова"})
}
})


//===============================================

//Эндпоинт 2
//api/auth/login
router.post(
    "/login", 
    //проводим валидацию
    [
check("email", "Введите корректный email").normalizeEmail().isEmail(),
check("password", "Введите пароль").exists()
    ],
    async (req,res)=>{
        try{
            //продолжаем валидацию
            const errors = validationResult(req)
            //если объект не пустой(есть какие-то ошибки), тогда я сразу же верну их на фронтенд
        if(!errors.isEmpty()){
            return res.status(400).json({
               errors: errors.array(),
               message:"Некорректные данные при входе в систему"
            })
        }

        //Получаем мэил и пороль от пользователя
        const {email, password}=req.body
        //Ищем пользователя в базе данных
         const user = await User.findOne({email})
         if(!user){
             return res.status(400).json({message:"Пользователь не найден"})
         }
//Проверяем, совпадают ли его пароли
const isMatch = await bcrypt.compare(password, user.password)
if(!isMatch){
    return res.status(400).json({message:"Неверный пароль попробуйте снова"})
}
//Если дошли до сюда, то с пользователем все хорошо и делаем авторизацию
const token = jwt.sign(
    {userId:user.id},
    config.get("jwtSecret"),
    {expiresIn:"1h"}
)

//Отвечаем клиенту
res.json({token, userId:user.id})
        }catch(e){
            res.status(500).json({message:"Что-то пошло не так, попробуйте снова"})
        }
        })
    

module.exports = router






