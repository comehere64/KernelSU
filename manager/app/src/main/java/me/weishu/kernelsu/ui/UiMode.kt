package me.weishu.kernelsu.ui

import androidx.compose.runtime.staticCompositionLocalOf

/**
 * 只有两档：官方 Material 3 与 miuix(原版)。
 * 美化版已移除；[Miuix] 仅作为历史值保留解析入口，运行时统一映射到 [MiuixStock]，
 * 避免旧配置（ui_mode=miuix）导致启动时找不到模式。
 */
enum class UiMode(val value: String, val displayName: String) {
    Material("material", "Material 3"),
    MiuixStock("miuix_stock", "miuix(原版)"),

    /** 兼容旧配置：不再出现在选择列表里，读写时归一到 MiuixStock。 */
    @Deprecated("美化版已移除")
    Miuix("miuix", "miuix(美化版)");

    companion object {
        /** 下拉里真正展示的两项。 */
        val selectable: List<UiMode> = listOf(Material, MiuixStock)

        fun fromValue(value: String): UiMode = when (value) {
            Miuix.value -> MiuixStock
            Material.value -> Material
            else -> MiuixStock
        }

        val DEFAULT_VALUE = Material.value
    }
}

val LocalUiMode = staticCompositionLocalOf { UiMode.Material }

/** 兼容旧代码：两种模式都算 miuix 结构（美化版已不存在）。 */
val UiMode.isMiuixFamily: Boolean
    get() = this == UiMode.MiuixStock || this == UiMode.Miuix
