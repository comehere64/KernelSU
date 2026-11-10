package me.weishu.kernelsu.ui.screen.settings

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import me.weishu.kernelsu.ui.util.CalculatorLauncher

/**
 * 计算器启动器的共享状态与动作。
 *
 * 两套界面风格（Material 3 / miuix 原版）都用同一份实现，只有外层容器不同，
 * 这样「安装 / 卸载 / 自定义触发码」的行为完全一致。
 */
@Composable
fun rememberCalculatorLauncherState(): CalculatorLauncherState {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    var installed by remember { mutableStateOf(false) }
    var dialogShown by remember { mutableStateOf(false) }
    var codeText by remember { mutableStateOf("") }

    LaunchedEffect(Unit) {
        withContext(Dispatchers.IO) {
            installed = CalculatorLauncher.isInstalled(context)
        }
    }

    return CalculatorLauncherState(
        installed = installed,
        dialogShown = dialogShown,
        codeText = codeText,
        onDialogShownChange = { dialogShown = it; if (!it) Unit },
        onCodeChange = { codeText = it },
        onToggle = { enable ->
            if (enable) {
                scope.launch {
                    codeText = withContext(Dispatchers.IO) {
                        CalculatorLauncher.readTriggerCode()
                    }.ifEmpty { "1234" }
                    dialogShown = true
                }
            } else {
                scope.launch {
                    installed = withContext(Dispatchers.IO) {
                        CalculatorLauncher.uninstall(context)
                        CalculatorLauncher.isInstalled(context)
                    }
                }
            }
        },
        onConfirm = {
            dialogShown = false
            scope.launch {
                installed = withContext(Dispatchers.IO) {
                    CalculatorLauncher.setTriggerCode(codeText)
                    CalculatorLauncher.install(context)
                    CalculatorLauncher.isInstalled(context)
                }
            }
        },
    )
}

data class CalculatorLauncherState(
    val installed: Boolean,
    val dialogShown: Boolean,
    val codeText: String,
    val onDialogShownChange: (Boolean) -> Unit,
    val onCodeChange: (String) -> Unit,
    val onToggle: (Boolean) -> Unit,
    val onConfirm: () -> Unit,
)

/** 两套风格共用的触发码对话框。 */
@Composable
fun CalculatorCodeDialog(
    state: CalculatorLauncherState,
) {
    if (!state.dialogShown) return
    AlertDialog(
        onDismissRequest = { state.onDialogShownChange(false) },
        title = { Text("自定义密码") },
        text = {
            Column {
                Text("在计算器里输入这串数字再按 = 就会打开网页管理器。只能填数字；留空表示用内置的默认值。")
                OutlinedTextField(
                    value = state.codeText,
                    onValueChange = { typed: String -> state.onCodeChange(typed.filter { it.isDigit() }) },
                    singleLine = true,
                    label = { Text("密码") },
                    modifier = Modifier
                        .padding(top = 12.dp)
                        .fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            TextButton(onClick = { state.onConfirm() }) { Text("确定") }
        },
        dismissButton = {
            TextButton(onClick = { state.onDialogShownChange(false) }) { Text("取消") }
        },
    )
}

/** 计算器卡片的两个文案，两套风格共用，保证措辞一致。 */
const val CALC_TITLE = "计算器启动器"
const val CALC_SUMMARY_ON = "已安装。在计算器里输入触发码按 = 即启动网页端；从最近任务划掉就关闭端口"
const val CALC_SUMMARY_OFF = "装一个计算器当入口：输入触发码按 = 启动网页端，不用时端口不监听"
