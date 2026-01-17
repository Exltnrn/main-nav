package main

import (
    "log"
    "net/http"
    "os"
    "strconv"

    "github.com/gin-gonic/gin"
    "github.com/glebarez/sqlite"
    "golang.org/x/crypto/bcrypt"
    "gorm.io/gorm"
)

var DB *gorm.DB

// User 用户模型
type User struct {
    ID       uint   `gorm:"primaryKey"`
    Username string `gorm:"unique"`
    Password string
}

// Settings 系统设置模型
type Settings struct {
    ID               uint   `gorm:"primaryKey"`
    Title            string `gorm:"default:'Main Nav'"`
    BgImageLogin     string
    BgImageDashboard string
}

// Category 分类模型
type Category struct {
    ID        uint   `gorm:"primaryKey"`
    Name      string
    SortOrder int    `gorm:"default:0"`
    Sites     []Site `gorm:"foreignKey:CategoryID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"` // 级联删除
}

// Site 网站模型
type Site struct {
    ID          uint   `gorm:"primaryKey"`
    Name        string
    Url         string
    Icon        string
    Description string
    SortOrder   int `gorm:"default:0"`
    CategoryID  uint
    Category    Category // 关联关系，用于 Preload
}

func InitDB() {
    if _, err := os.Stat("./data"); os.IsNotExist(err) {
        os.Mkdir("./data", 0755)
    }

    var err error
    DB, err = gorm.Open(sqlite.Open("data/nav.db"), &gorm.Config{})
    if err != nil {
        log.Fatal("无法连接数据库:", err)
    }

    DB.AutoMigrate(&User{}, &Settings{}, &Category{}, &Site{})

    // 初始化默认设置
    var setting Settings
    if result := DB.First(&setting); result.Error != nil {
        DB.Create(&Settings{Title: "Main Nav"})
    }

    // 初始化默认分类
    var cat Category
    if result := DB.First(&cat, 1); result.Error != nil {
        DB.Create(&Category{Name: "默认分类", SortOrder: 0})
    }
}

func main() {
    InitDB()

    r := gin.Default()
    r.LoadHTMLGlob("templates/*")
    r.Static("/static", "./static")

    // 登录验证中间件
    authMiddleware := func(c *gin.Context) {
        cookie, err := c.Cookie("user_id")
        if err != nil || cookie == "" {
            c.Redirect(http.StatusFound, "/login")
            c.Abort()
            return
        }
        c.Next()
    }

    // 首页
    r.GET("/", authMiddleware, func(c *gin.Context) {
        username, _ := c.Cookie("user_id")

        var settings Settings
        DB.First(&settings)

        var categories []Category
        DB.Preload("Sites", func(db *gorm.DB) *gorm.DB {
            return db.Order("sort_order asc")
        }).Order("sort_order asc").Find(&categories)

        c.HTML(http.StatusOK, "index.html", gin.H{
            "Categories": categories,
            "Settings":   settings,
            "Username":   username,
        })
    })

    // 设置页
    r.GET("/settings", authMiddleware, func(c *gin.Context) {
        var settings Settings
        DB.First(&settings)

        var categories []Category
        DB.Order("sort_order asc").Find(&categories)

        var sites []Site
        // 按 ID 倒序排列
        DB.Preload("Category").Order("id desc").Find(&sites)

        c.HTML(http.StatusOK, "settings.html", gin.H{
            "Settings":   settings,
            "Categories": categories,
            "Sites":      sites,
        })
    })

    // 更新全局设置
    r.POST("/settings/update", authMiddleware, func(c *gin.Context) {
        var settings Settings
        DB.First(&settings)
        settings.Title = c.PostForm("title")
        settings.BgImageDashboard = c.PostForm("bg_dashboard")
        settings.BgImageLogin = c.PostForm("bg_login")
        DB.Save(&settings)
        c.Redirect(http.StatusFound, "/settings")
    })

    // 添加分类
    r.POST("/category/add", authMiddleware, func(c *gin.Context) {
        name := c.PostForm("name")
        order, _ := strconv.Atoi(c.PostForm("sort_order"))
        DB.Create(&Category{Name: name, SortOrder: order})
        c.Redirect(http.StatusFound, "/settings")
    })

    // 删除分类
    r.POST("/category/delete", authMiddleware, func(c *gin.Context) {
        id := c.PostForm("id")
        DB.Delete(&Category{}, id)
        c.Redirect(http.StatusFound, "/settings")
    })

    // 添加网站
    r.POST("/site/add", authMiddleware, func(c *gin.Context) {
        catID, _ := strconv.Atoi(c.PostForm("category_id"))
        order, _ := strconv.Atoi(c.PostForm("sort_order"))

        site := Site{
            Name:        c.PostForm("name"),
            Url:         c.PostForm("url"),
            Icon:        c.PostForm("icon"),
            Description: c.PostForm("description"),
            CategoryID:  uint(catID),
            SortOrder:   order,
        }
        DB.Create(&site)
        c.Redirect(http.StatusFound, "/settings")
    })

    // 删除网站
    r.POST("/site/delete", authMiddleware, func(c *gin.Context) {
        id := c.PostForm("id")
        DB.Delete(&Site{}, id)
        c.Redirect(http.StatusFound, "/settings")
    })

    // 登录页面
    r.GET("/login", func(c *gin.Context) {
        var count int64
        DB.Model(&User{}).Count(&count)

        if count == 0 {
            c.HTML(http.StatusOK, "register.html", gin.H{"Message": "系统初始化：请创建管理员账号"})
            return
        }

        var settings Settings
        DB.First(&settings)
        c.HTML(http.StatusOK, "login.html", gin.H{"Settings": settings})
    })

    // 注册提交
    r.POST("/register", func(c *gin.Context) {
        username := c.PostForm("username")
        password := c.PostForm("password")

        var count int64
        DB.Model(&User{}).Count(&count)
        if count > 0 {
            c.String(403, "管理员已存在，禁止注册")
            return
        }

        hashed, _ := bcrypt.GenerateFromPassword([]byte(password), 14)
        DB.Create(&User{Username: username, Password: string(hashed)})
        c.Redirect(http.StatusFound, "/login")
    })

    // 登录提交
    r.POST("/login", func(c *gin.Context) {
        username := c.PostForm("username")
        password := c.PostForm("password")

        var user User
        if err := DB.Where("username = ?", username).First(&user).Error; err != nil {
            c.HTML(200, "login.html", gin.H{"Error": "用户不存在"})
            return
        }

        if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
            c.HTML(200, "login.html", gin.H{"Error": "密码错误"})
            return
        }

        c.SetCookie("user_id", username, 3600*24, "/", "", false, true)
        c.Redirect(http.StatusFound, "/")
    })

    r.Run(":8080")
}
