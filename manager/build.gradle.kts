plugins {
    alias(libs.plugins.agp.app) apply false
    alias(libs.plugins.kotlin) apply false
    alias(libs.plugins.compose.compiler) apply false
}

extra["androidMinSdkVersion"] = 31
extra["androidTargetSdkVersion"] = 37
extra["androidCompileSdkVersion"] = 37
extra["androidCompileSdkVersionMinor"] = 0
extra["androidBuildToolsVersion"] = "37.0.0"
extra["androidCompileNdkVersion"] = libs.versions.ndk.get()
extra["androidSourceCompatibility"] = JavaVersion.VERSION_21
extra["androidTargetCompatibility"] = JavaVersion.VERSION_21
extra["managerVersionCode"] = getVersionCode()
extra["managerVersionName"] = getVersionName()

fun gitOutput(vararg args: String): String? = runCatching {
    val pb = ProcessBuilder(*args)
    pb.directory(rootDir)
    pb.redirectErrorStream(false)
    val proc = pb.start()
    val text = proc.inputStream.bufferedReader().use { it.readText() }.trim()
    proc.waitFor()
    text.ifEmpty { null }
}.getOrNull()

fun getGitCommitCount(): Int {
    // 在 Termux 里 daemon 的工作目录不是仓库，必须显式 -C。
    val out = gitOutput("git", "-C", rootDir.absolutePath, "rev-list", "--count", "HEAD")
        ?: return 0
    return out.toIntOrNull() ?: 0
}

fun getGitDescribe(): String {
    return gitOutput("git", "-C", rootDir.absolutePath, "describe", "--tags", "--always")
        ?: "dev"
}

fun getVersionCode(): Int {
    val commitCount = getGitCommitCount()
    return 30000 + commitCount
}

fun getVersionName(): String {
    return getGitDescribe()
}
