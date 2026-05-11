/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  kotlin.Metadata
 *  kotlin.collections.CollectionsKt
 *  kotlin.jvm.functions.Function0
 *  kotlin.jvm.internal.Intrinsics
 *  kotlin.jvm.internal.SourceDebugExtension
 *  kotlin.sequences.Sequence
 *  kotlin.sequences.SequencesKt
 *  kotlin.text.StringsKt
 *  org.jetbrains.annotations.NotNull
 *  org.springframework.data.redis.core.RedisTemplate
 *  org.springframework.data.redis.core.ValueOperations
 *  org.springframework.stereotype.Service
 */
package com.teamsa.piggybank.user.service;

import com.teamsa.piggybank.user.UserConstants;
import com.teamsa.piggybank.user.domain.User;
import com.teamsa.piggybank.user.repository.UserRepository;
import com.teamsa.piggybank.user.service.UserPasswordResetService;
import com.teamsa.piggybank.user.service.UserService;
import com.teamsa.piggybank.user.service.UserServiceException;
import com.teamsa.piggybank.util.PasswordHashKt;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.SourceDebugExtension;
import kotlin.sequences.Sequence;
import kotlin.sequences.SequencesKt;
import kotlin.text.StringsKt;
import org.jetbrains.annotations.NotNull;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Service;

@Service
@Metadata(mv={1, 9, 0}, k=1, xi=48, d1={"\u0000R\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0010\t\n\u0002\b\u0007\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010 \n\u0002\b\u0014\b\u0017\u0018\u00002\u00020\u0001B)\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0012\u0010\u0004\u001a\u000e\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\u00010\u0005\u0012\u0006\u0010\u0007\u001a\u00020\b\u00a2\u0006\u0002\u0010\tJ\u0010\u0010 \u001a\u00020!2\u0006\u0010\"\u001a\u00020\u0006H\u0016J\u0010\u0010#\u001a\u00020$2\u0006\u0010%\u001a\u00020\u001aH\u0016J \u0010&\u001a\b\u0012\u0004\u0012\u00020\u001a0'2\u0006\u0010\"\u001a\u00020\u00062\b\b\u0002\u0010(\u001a\u00020!H\u0016J\u0010\u0010)\u001a\u00020\u00062\u0006\u0010*\u001a\u00020\u0006H\u0016J\u001e\u0010+\u001a\u00020\u00062\u0006\u0010\"\u001a\u00020\u00062\f\u0010,\u001a\b\u0012\u0004\u0012\u00020\u00060'H\u0016J \u0010-\u001a\u00020$2\u0006\u0010.\u001a\u00020\u00062\u0006\u0010/\u001a\u00020\u00062\u0006\u00100\u001a\u00020\u0006H\u0016J\u0010\u00101\u001a\u00020!2\u0006\u00102\u001a\u00020\u0006H\u0016J\u0010\u00103\u001a\u00020\u001a2\u0006\u0010\"\u001a\u00020\u0006H\u0016J\u0010\u00104\u001a\u00020\u00062\u0006\u0010\"\u001a\u00020\u0006H\u0016J\u0010\u00105\u001a\u00020\u00062\u0006\u0010\"\u001a\u00020\u0006H\u0016J\u0010\u00106\u001a\u00020!2\u0006\u0010\"\u001a\u00020\u0006H\u0016J\u0010\u00107\u001a\u00020!2\u0006\u0010.\u001a\u00020\u0006H\u0016J\u0018\u00108\u001a\u00020$2\u0006\u0010\"\u001a\u00020\u00062\u0006\u00109\u001a\u00020\u001aH\u0016J\u0010\u0010:\u001a\u00020$2\u0006\u0010\"\u001a\u00020\u0006H\u0016R\u0014\u0010\n\u001a\u00020\u0006X\u0096D\u00a2\u0006\b\n\u0000\u001a\u0004\b\u000b\u0010\fR\u0014\u0010\r\u001a\u00020\u0006X\u0096D\u00a2\u0006\b\n\u0000\u001a\u0004\b\u000e\u0010\fR\u0014\u0010\u000f\u001a\u00020\u0006X\u0096D\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0010\u0010\fR\u0014\u0010\u0011\u001a\u00020\u0012X\u0096D\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0013\u0010\u0014R\u0014\u0010\u0015\u001a\u00020\u0006X\u0096D\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0016\u0010\fR\u0014\u0010\u0017\u001a\u00020\u0006X\u0096D\u00a2\u0006\b\n\u0000\u001a\u0004\b\u0018\u0010\fR\u0014\u0010\u0019\u001a\u00020\u001aX\u0096D\u00a2\u0006\b\n\u0000\u001a\u0004\b\u001b\u0010\u001cR*\u0010\u001d\u001a\u001e\u0012\f\u0012\n \u001f*\u0004\u0018\u00010\u00060\u0006\u0012\f\u0012\n \u001f*\u0004\u0018\u00010\u00010\u00010\u001eX\u0092\u0004\u00a2\u0006\u0002\n\u0000R\u001a\u0010\u0004\u001a\u000e\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\u00010\u0005X\u0092\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0002\u001a\u00020\u0003X\u0092\u0004\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0007\u001a\u00020\bX\u0092\u0004\u00a2\u0006\u0002\n\u0000\u00a8\u0006;"}, d2={"Lcom/teamsa/piggybank/user/service/UserPasswordResetService;", "", "userRepository", "Lcom/teamsa/piggybank/user/repository/UserRepository;", "redisTemplate", "Lorg/springframework/data/redis/core/RedisTemplate;", "", "userService", "Lcom/teamsa/piggybank/user/service/UserService;", "(Lcom/teamsa/piggybank/user/repository/UserRepository;Lorg/springframework/data/redis/core/RedisTemplate;Lcom/teamsa/piggybank/user/service/UserService;)V", "CHALLENGE_INDEX_PREFIX", "getCHALLENGE_INDEX_PREFIX", "()Ljava/lang/String;", "CHALLENGE_TOKEN_PREFIX", "getCHALLENGE_TOKEN_PREFIX", "CONFIG_PREFIX", "getCONFIG_PREFIX", "KEY_EXPIRATION_TIME", "", "getKEY_EXPIRATION_TIME", "()J", "LOCK_PREFIX", "getLOCK_PREFIX", "PASS_TOKEN_PREFIX", "getPASS_TOKEN_PREFIX", "RATE_LIMIT", "", "getRATE_LIMIT", "()I", "redis", "Lorg/springframework/data/redis/core/ValueOperations;", "kotlin.jvm.PlatformType", "canLock", "", "challengeToken", "checkRateLimit", "", "count", "createChallenge", "", "mode", "createChallengeToken", "username", "doChallenge", "answer", "doChangePassword", "passResetToken", "firstPassword", "secondPassword", "findUser", "userName", "getRateLimit", "getUserId", "getUsername", "isExistChallengeToken", "isExistPassResetToken", "setRateLimit", "rateLimitCount", "setUnLock", "piggybank"})
@SourceDebugExtension(value={"SMAP\nUserPasswordResetService.kt\nKotlin\n*S Kotlin\n*F\n+ 1 UserPasswordResetService.kt\ncom/teamsa/piggybank/user/service/UserPasswordResetService\n+ 2 _Collections.kt\nkotlin/collections/CollectionsKt___CollectionsKt\n*L\n1#1,198:1\n1549#2:199\n1620#2,3:200\n1549#2:203\n1620#2,3:204\n*S KotlinDebug\n*F\n+ 1 UserPasswordResetService.kt\ncom/teamsa/piggybank/user/service/UserPasswordResetService\n*L\n52#1:199\n52#1:200,3\n80#1:203\n80#1:204,3\n*E\n"})
public class UserPasswordResetService {
    @NotNull
    private final UserRepository userRepository;
    @NotNull
    private final RedisTemplate<String, Object> redisTemplate;
    @NotNull
    private final UserService userService;
    @NotNull
    private final ValueOperations<String, Object> redis;
    @NotNull
    private final String CONFIG_PREFIX;
    @NotNull
    private final String LOCK_PREFIX;
    @NotNull
    private final String CHALLENGE_TOKEN_PREFIX;
    @NotNull
    private final String CHALLENGE_INDEX_PREFIX;
    @NotNull
    private final String PASS_TOKEN_PREFIX;
    private final long KEY_EXPIRATION_TIME;
    private final int RATE_LIMIT;

    public UserPasswordResetService(@NotNull UserRepository userRepository, @NotNull RedisTemplate<String, Object> redisTemplate, @NotNull UserService userService) {
        Intrinsics.checkNotNullParameter((Object)userRepository, (String)"userRepository");
        Intrinsics.checkNotNullParameter(redisTemplate, (String)"redisTemplate");
        Intrinsics.checkNotNullParameter((Object)userService, (String)"userService");
        this.userRepository = userRepository;
        this.redisTemplate = redisTemplate;
        this.userService = userService;
        ValueOperations valueOperations = this.redisTemplate.opsForValue();
        Intrinsics.checkNotNullExpressionValue((Object)valueOperations, (String)"opsForValue(...)");
        this.redis = valueOperations;
        this.CONFIG_PREFIX = "CONFIG";
        this.LOCK_PREFIX = "LOCK";
        this.CHALLENGE_TOKEN_PREFIX = "CHALLENGE:TOKEN";
        this.CHALLENGE_INDEX_PREFIX = "CHALLENGE:INDEX";
        this.PASS_TOKEN_PREFIX = "PASS:TOKEN";
        this.KEY_EXPIRATION_TIME = 30L;
        this.RATE_LIMIT = 8;
    }

    @NotNull
    public String getCONFIG_PREFIX() {
        return this.CONFIG_PREFIX;
    }

    @NotNull
    public String getLOCK_PREFIX() {
        return this.LOCK_PREFIX;
    }

    @NotNull
    public String getCHALLENGE_TOKEN_PREFIX() {
        return this.CHALLENGE_TOKEN_PREFIX;
    }

    @NotNull
    public String getCHALLENGE_INDEX_PREFIX() {
        return this.CHALLENGE_INDEX_PREFIX;
    }

    @NotNull
    public String getPASS_TOKEN_PREFIX() {
        return this.PASS_TOKEN_PREFIX;
    }

    public long getKEY_EXPIRATION_TIME() {
        return this.KEY_EXPIRATION_TIME;
    }

    public int getRATE_LIMIT() {
        return this.RATE_LIMIT;
    }

    @NotNull
    public String createChallengeToken(@NotNull String username) {
        Intrinsics.checkNotNullParameter((Object)username, (String)"username");
        String string = UUID.randomUUID().toString();
        Intrinsics.checkNotNullExpressionValue((Object)string, (String)"toString(...)");
        String challengeToken = string;
        String challengeKey = this.getCHALLENGE_TOKEN_PREFIX() + ":" + challengeToken;
        this.redis.set((Object)challengeKey, (Object)username);
        this.redisTemplate.expire((Object)challengeKey, this.getKEY_EXPIRATION_TIME(), TimeUnit.MINUTES);
        return challengeToken;
    }

    /*
     * WARNING - void declaration
     */
    @NotNull
    public List<Integer> createChallenge(@NotNull String challengeToken, boolean mode) {
        Intrinsics.checkNotNullParameter((Object)challengeToken, (String)"challengeToken");
        if (Intrinsics.areEqual((Object)challengeToken, (Object)"") || !this.isExistChallengeToken(challengeToken)) {
            throw new UserServiceException("\uc62c\ubc14\ub974\uc9c0 \uc54a\uc740 challenge token \uac12\uc785\ub2c8\ub2e4.");
        }
        String key = this.getCHALLENGE_INDEX_PREFIX() + ":" + challengeToken;
        Object prevChallenge = this.redis.get((Object)key);
        if (mode && prevChallenge != null) {
            void $this$mapTo$iv$iv;
            String[] stringArray = new String[]{","};
            Iterable $this$map$iv = StringsKt.split$default((CharSequence)prevChallenge.toString(), (String[])stringArray, (boolean)false, (int)0, (int)6, null);
            boolean $i$f$map = false;
            Iterable iterable = $this$map$iv;
            Collection destination$iv$iv = new ArrayList(CollectionsKt.collectionSizeOrDefault((Iterable)$this$map$iv, (int)10));
            boolean $i$f$mapTo = false;
            for (Object item$iv$iv : $this$mapTo$iv$iv) {
                void it;
                String string = (String)item$iv$iv;
                Collection collection = destination$iv$iv;
                boolean bl = false;
                collection.add(Integer.parseInt((String)it));
            }
            return (List)destination$iv$iv;
        }
        List randomIndex = CollectionsKt.emptyList();
        while ((randomIndex = CollectionsKt.sorted((Iterable)CollectionsKt.toList((Iterable)SequencesKt.toSet((Sequence)SequencesKt.take((Sequence)SequencesKt.distinct((Sequence)SequencesKt.generateSequence((Function0)createChallenge.2.INSTANCE)), (int)UserConstants.INSTANCE.getSECURE_CODE_INDEX()))))).size() != UserConstants.INSTANCE.getSECURE_CODE_INDEX()) {
        }
        String value = CollectionsKt.joinToString$default((Iterable)randomIndex, (CharSequence)",", null, null, (int)0, null, null, (int)62, null);
        this.redis.set((Object)key, (Object)value);
        this.redisTemplate.expire((Object)key, this.getKEY_EXPIRATION_TIME(), TimeUnit.MINUTES);
        return randomIndex;
    }

    public static /* synthetic */ List createChallenge$default(UserPasswordResetService userPasswordResetService, String string, boolean bl, int n, Object object) {
        if (object != null) {
            throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: createChallenge");
        }
        if ((n & 2) != 0) {
            bl = true;
        }
        return userPasswordResetService.createChallenge(string, bl);
    }

    /*
     * WARNING - void declaration
     */
    @NotNull
    public String doChallenge(@NotNull String challengeToken, @NotNull List<String> answer) {
        Intrinsics.checkNotNullParameter((Object)challengeToken, (String)"challengeToken");
        Intrinsics.checkNotNullParameter(answer, (String)"answer");
        String passResetToken = "";
        if (Intrinsics.areEqual((Object)challengeToken, (Object)"") || !this.isExistChallengeToken(challengeToken)) {
            throw new UserServiceException("\uc62c\ubc14\ub974\uc9c0 \uc54a\uc740 challenge token \uac12 \uc785\ub2c8\ub2e4.");
        }
        try {
            if (this.canLock(challengeToken)) {
                Collection destination$iv$iv;
                Object $this$map$iv;
                String[] stringArray;
                Object object = this.redis.get((Object)(this.getCHALLENGE_INDEX_PREFIX() + ":" + challengeToken));
                if (object != null && (object = object.toString()) != null && (object = StringsKt.split$default((CharSequence)((CharSequence)object), (String[])(stringArray = new String[]{","}), (boolean)false, (int)0, (int)6, null)) != null) {
                    void $this$mapTo$iv$iv;
                    $this$map$iv = (Iterable)object;
                    boolean $i$f$map = false;
                    Iterable iterable = $this$map$iv;
                    destination$iv$iv = new ArrayList(CollectionsKt.collectionSizeOrDefault((Iterable)$this$map$iv, (int)10));
                    boolean $i$f$mapTo = false;
                    for (Object item$iv$iv : $this$mapTo$iv$iv) {
                        void it;
                        String string = (String)item$iv$iv;
                        Collection collection = destination$iv$iv;
                        boolean bl = false;
                        collection.add(Integer.parseInt((String)it));
                    }
                } else {
                    throw new UserServiceException("challenge \ucf54\ub4dc\uac00 \ub9cc\ub8cc\ub418\uc5c8\uc2b5\ub2c8\ub2e4.");
                }
                List challengeIndex = (List)destination$iv$iv;
                Object object2 = this.redis.get((Object)(this.getCHALLENGE_TOKEN_PREFIX() + ":" + challengeToken));
                if (object2 == null || (object2 = object2.toString()) == null) {
                    throw new UserServiceException("challenge token\uc774 \ub9cc\ub8cc\ub418\uc5c8\uc2b5\ub2c8\ub2e4.");
                }
                Object userName = object2;
                User user = this.userRepository.findUserByUsername((String)userName);
                if (user == null) {
                    throw new UserServiceException("\uc608\uc0c1\uce58 \ubabb\ud55c \uc5d0\ub7ec\uac00 \ubc1c\uc0dd \ud588\uc2b5\ub2c8\ub2e4.");
                }
                User userInfo = user;
                stringArray = new String[]{","};
                List userSecureCode = StringsKt.split$default((CharSequence)userInfo.getSecureCode(), (String[])stringArray, (boolean)false, (int)0, (int)6, null);
                int rateLimitCount = this.getRateLimit(challengeToken);
                Thread.sleep(8000L);
                this.checkRateLimit(rateLimitCount);
                $this$map$iv = challengeIndex.iterator();
                int n = 0;
                while ($this$map$iv.hasNext()) {
                    int index = n++;
                    int challIndex = ((Number)$this$map$iv.next()).intValue();
                    if (Intrinsics.areEqual(userSecureCode.get(challIndex - 1), (Object)answer.get(index))) continue;
                    this.setRateLimit(challengeToken, rateLimitCount + 1);
                    throw new UserServiceException("\uc62c\ubc14\ub974\uc9c0 \uc54a\uc740 secure code \uc785\ub2c8\ub2e4. \uc2e4\ud328 \ud69f\uc218: " + (rateLimitCount + 1));
                }
                String string = UUID.randomUUID().toString();
                Intrinsics.checkNotNullExpressionValue((Object)string, (String)"toString(...)");
                passResetToken = string;
                String passKey = this.getPASS_TOKEN_PREFIX() + ":" + passResetToken;
                this.setUnLock(challengeToken);
                this.redis.set((Object)passKey, userName);
                this.redisTemplate.expire((Object)passKey, this.getKEY_EXPIRATION_TIME(), TimeUnit.MINUTES);
                this.redisTemplate.delete((Object)(this.getCHALLENGE_TOKEN_PREFIX() + ":" + challengeToken));
                this.redisTemplate.delete((Object)(this.getCHALLENGE_INDEX_PREFIX() + ":" + challengeToken));
            }
        }
        catch (UserServiceException e) {
            this.setUnLock(challengeToken);
            throw new UserServiceException(String.valueOf(e.getMessage()));
        }
        catch (Exception e) {
            this.setUnLock(challengeToken);
            throw new UserServiceException("\uc54c \uc218 \uc5c6\ub294 \uc5d0\ub7ec \uc785\ub2c8\ub2e4.");
        }
        return passResetToken;
    }

    public boolean findUser(@NotNull String userName) {
        Intrinsics.checkNotNullParameter((Object)userName, (String)"userName");
        return this.userRepository.existsByUsername(userName);
    }

    public boolean isExistChallengeToken(@NotNull String challengeToken) {
        Intrinsics.checkNotNullParameter((Object)challengeToken, (String)"challengeToken");
        return this.redis.get((Object)(this.getCHALLENGE_TOKEN_PREFIX() + ":" + challengeToken)) != null;
    }

    public boolean isExistPassResetToken(@NotNull String passResetToken) {
        Intrinsics.checkNotNullParameter((Object)passResetToken, (String)"passResetToken");
        return this.redis.get((Object)(this.getPASS_TOKEN_PREFIX() + ":" + passResetToken)) != null;
    }

    public void checkRateLimit(int count) {
        if (count >= this.getRATE_LIMIT()) {
            throw new UserServiceException("\ub354\uc774\uc0c1 \ud328\uc2a4\uc6cc\ub4dc\ub97c \ucd08\uae30\ud654 \ud560 \uc218 \uc5c6\uc2b5\ub2c8\ub2e4. \uad00\ub77c\uc790\uc5d0\uac8c \ubb38\uc758\ud574 \uc8fc\uc138\uc694.");
        }
    }

    public int getRateLimit(@NotNull String challengeToken) {
        Intrinsics.checkNotNullParameter((Object)challengeToken, (String)"challengeToken");
        String userName = this.getUsername(challengeToken);
        String rateLimitKey = this.getCONFIG_PREFIX() + ":" + userName;
        Object object = this.redis.get((Object)rateLimitKey);
        return object != null && (object = object.toString()) != null ? Integer.parseInt((String)object) : 0;
    }

    public void setRateLimit(@NotNull String challengeToken, int rateLimitCount) {
        Intrinsics.checkNotNullParameter((Object)challengeToken, (String)"challengeToken");
        String userName = this.getUsername(challengeToken);
        String rateLimitKey = this.getCONFIG_PREFIX() + ":" + userName;
        this.redis.set((Object)rateLimitKey, (Object)String.valueOf(rateLimitCount));
    }

    @NotNull
    public String getUsername(@NotNull String challengeToken) {
        Intrinsics.checkNotNullParameter((Object)challengeToken, (String)"challengeToken");
        return String.valueOf(this.redis.get((Object)(this.getCHALLENGE_TOKEN_PREFIX() + ":" + challengeToken)));
    }

    @NotNull
    public String getUserId(@NotNull String challengeToken) {
        Intrinsics.checkNotNullParameter((Object)challengeToken, (String)"challengeToken");
        String userName = this.getUsername(challengeToken);
        User user = this.userRepository.findUserByUsername(userName);
        if (user == null) {
            throw new UserServiceException("\uc874\uc7ac\ud558\uc9c0 \uc54a\ub294 \uc720\uc800 \uc785\ub2c8\ub2e4.");
        }
        User user2 = user;
        return user2.getId();
    }

    public boolean canLock(@NotNull String challengeToken) {
        Boolean bl;
        boolean isLockSet;
        Intrinsics.checkNotNullParameter((Object)challengeToken, (String)"challengeToken");
        String userId = this.getUserId(challengeToken);
        String lockKey = this.getCONFIG_PREFIX() + ":" + this.getLOCK_PREFIX() + ":" + userId;
        do {
            if ((bl = this.redis.setIfAbsent((Object)lockKey, (Object)"1")) != null) continue;
            bl = false;
        } while (!(isLockSet = bl.booleanValue()));
        return true;
    }

    public void setUnLock(@NotNull String challengeToken) {
        Intrinsics.checkNotNullParameter((Object)challengeToken, (String)"challengeToken");
        String userId = this.getUserId(challengeToken);
        this.redisTemplate.delete((Object)(this.getCONFIG_PREFIX() + ":" + this.getLOCK_PREFIX() + ":" + userId));
    }

    public void doChangePassword(@NotNull String passResetToken, @NotNull String firstPassword, @NotNull String secondPassword) {
        Intrinsics.checkNotNullParameter((Object)passResetToken, (String)"passResetToken");
        Intrinsics.checkNotNullParameter((Object)firstPassword, (String)"firstPassword");
        Intrinsics.checkNotNullParameter((Object)secondPassword, (String)"secondPassword");
        if (!this.isExistPassResetToken(passResetToken)) {
            throw new UserServiceException("\uc874\uc7ac\ud558\uc9c0 \uc54a\ub294 pass_reset_token \uc785\ub2c8\ub2e4.");
        }
        if (firstPassword.length() < 8 || firstPassword.length() > 64) {
            throw new UserServiceException("\ube44\ubc00\ubc88\ud638 \uae38\uc774\ub97c \ud655\uc778\ud574\uc8fc\uc138\uc694.");
        }
        if (!Intrinsics.areEqual((Object)firstPassword, (Object)secondPassword)) {
            throw new UserServiceException("\uc785\ub825\ud55c \ube44\ubc00\ubc88\ud638\uac00 \ub3d9\uc77c\ud558\uc9c0 \uc54a\uc2b5\ub2c8\ub2e4.");
        }
        Object object = this.redis.get((Object)(this.getPASS_TOKEN_PREFIX() + ":" + passResetToken));
        Intrinsics.checkNotNull((Object)object);
        String userName = object.toString();
        User user = this.userRepository.findUserByUsername(userName);
        if (user == null) {
            throw new UserServiceException("\uc608\uc0c1\uce58 \ubabb\ud55c \uc5d0\ub7ec\uac00 \ubc1c\uc0dd \ud588\uc2b5\ub2c8\ub2e4.");
        }
        User user2 = user;
        String hashedPassword = PasswordHashKt.sha256(firstPassword);
        user2.updatePassword(hashedPassword);
        this.userRepository.save(user2);
        this.redisTemplate.delete((Object)(this.getCONFIG_PREFIX() + ":" + userName));
    }
}
