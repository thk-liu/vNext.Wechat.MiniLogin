# vNext.Wechat.MiniLogin
abp vNext 微信小程序登录模块

## 扩展Ids4小程序自定义验证方式
```C#
 public class WeChatMiniProgramGrantValidator : IExtensionGrantValidator,ITransientDependency
    {
        public string GrantType => "WeChatMiniProgram_credentials";

        private readonly IdentityUserManager _userManager;

        public string LoginProvider => "WechatMiniProgram";


        public WeChatMiniProgramGrantValidator(IdentityUserManager userManager)
        {
            _userManager = userManager;
        }

        public async Task ValidateAsync(ExtensionGrantValidationContext context)
        {
            
            var openId = context.Request.Raw.Get("openid");
            var errorValidationResult = new GrantValidationResult(TokenRequestErrors.InvalidGrant);
            if (string.IsNullOrWhiteSpace(openId))
            {
                errorValidationResult.ErrorDescription = "openId不能为空";
                context.Result = errorValidationResult;
                return;
            }
            
            var iUser = await _userManager.FindByLoginAsync(LoginProvider, openId);


            if (iUser != null&&iUser!=default(IdentityUser))
            {
                var Claims = new List<Claim>();
                Claims.Add(new Claim(AbpClaimTypes.Role, iUser.Roles.ToString()));
                Claims.Add(new Claim(AbpClaimTypes.Email, iUser.Email??""));
                Claims.Add(new Claim(AbpClaimTypes.EmailVerified, iUser.EmailConfirmed.ToString()));
                Claims.Add(new Claim(AbpClaimTypes.PhoneNumber,iUser.PhoneNumber??""));
                Claims.Add(new Claim(AbpClaimTypes.PhoneNumberVerified, iUser.PhoneNumberConfirmed.ToString()));
                Claims.Add(new Claim(AbpClaimTypes.UserName, iUser.UserName??""));
                Claims.Add(new Claim(AbpClaimTypes.UserId, iUser.Id.ToString()));

                foreach (var item in iUser.Claims)
                {
                    Claims.Add(new Claim(item.ClaimType, item.ClaimValue));
                }
                context.Result = new GrantValidationResult(iUser.Id.ToString(), GrantType, Claims);
            }
            else
            {
                errorValidationResult.ErrorDescription = "微信快捷登录失败 openId:"+openId;
                context.Result = errorValidationResult;
                return;
            }
        }
    }
```
### 微信登录方式，兼容初次登录与后续登录
```C#
[Produces ("application/json")]
        [HttpGet ("WeChatMiniLogin")]
        public async Task<IActionResult> WeChatMiniLogin (string code) {

            var needAdvanced = true;
            //调用第三方服务通过小程序内部登录后的Code获取微信Session信息
            var wechatSession = await WechatAppService.GetWeChatSessionAsync (code);
            //通过Provider和Openid获取用户的登录信息
            var wechatLogin = await _userManager.FindByLoginAsync (WechatMiniProgramLoginProvider, wechatSession.Openid);

            //首次微信登陆
            if (wechatLogin == null) {
                var idUserLoginInfo = new Microsoft.AspNetCore.Identity.UserLoginInfo (WechatMiniProgramLoginProvider, wechatSession.Openid, "微信小程序");
                if (!CurrentUser.Id.HasValue) {
                    //未有值采取默认注册
                    Logger.LogInformation ("未有值采取默认注册");
                    var iduser = new IdentityUser (Guid.NewGuid (), wechatSession.Openid, email : wechatSession.Openid + "@wechat", tenantId : CurrentTenant.Id);
                    iduser.ExtraProperties.AddWeChatUserInfo (new WeChatUserInfo { OpenId = wechatSession.Openid });
                    iduser.AddLogin (idUserLoginInfo);

                    await _userManager.CreateAsync (iduser);
                } else {
                    Logger.LogInformation("当前用户已授权值");
                    var user = await _userManager.GetByIdAsync (CurrentUser.Id.Value);
                    //UserClaims优化后 这里可以不需要该信息了
                    if (user.ExtraProperties.GetWeChatUserInfo ().HasData ()) {
                        //头像 昵称 等有一个不存在值 才需要高级授权
                        needAdvanced = false;
                    }
                    await _userManager.AddLoginAsync (user, idUserLoginInfo);
                }
            }
            var tokenReponse = await RequestTokenByOpenIdAsync (wechatSession.Openid);

            return Json (new { needAdvanced, wechatSession, tokenReponse.AccessToken });
        }

```
