################################################################################
# Automatically-generated file. Do not edit!
################################################################################

SHELL = cmd.exe

# Each subdirectory must supply rules for building sources it contributes
%.obj: ../%.c $(GEN_OPTS) | $(GEN_FILES) $(GEN_MISC_FILES)
	@echo 'Building file: "$<"'
	@echo 'Invoking: ARM Compiler'
	"C:/ti/ccs930/ccs/tools/compiler/ti-cgt-arm_18.12.4.LTS/bin/armcl" -mv7M4 --code_state=16 --float_support=FPv4SPD16 -me -Ooff --include_path="C:/Users/davej/workspace_v9/Final_8Ball_DavidJ" --include_path="C:/TI/CC3200SDK_1.5.0/cc3200-sdk/simplelink/" --include_path="C:/TI/CC3200SDK_1.5.0/cc3200-sdk/simplelink/include" --include_path="C:/TI/CC3200SDK_1.5.0/cc3200-sdk/simplelink/source" --include_path="C:/TI/CC3200SDK_1.5.0/cc3200-sdk/driverlib/" --include_path="C:/TI/CC3200SDK_1.5.0/cc3200-sdk/inc/" --include_path="C:/TI/CC3200SDK_1.5.0/cc3200-sdk/example/common/" --include_path="C:/TI/CC3200SDK_1.5.0/cc3200-sdk/simplelink_extlib/provisioninglib" --include_path="C:/ti/ccs930/ccs/tools/compiler/ti-cgt-arm_18.12.4.LTS/include" --define=ccs --define=cc3200 -g --diag_warning=225 --diag_wrap=off --display_error_number --abi=eabi --preproc_with_compile --preproc_dependency="$(basename $(<F)).d_raw" $(GEN_OPTS__FLAG) "$<"
	@echo 'Finished building: "$<"'
	@echo ' '

gpio_if.obj: C:/ti/CC3200SDK_1.5.0/cc3200-sdk/example/common/gpio_if.c $(GEN_OPTS) | $(GEN_FILES) $(GEN_MISC_FILES)
	@echo 'Building file: "$<"'
	@echo 'Invoking: ARM Compiler'
	"C:/ti/ccs930/ccs/tools/compiler/ti-cgt-arm_18.12.4.LTS/bin/armcl" -mv7M4 --code_state=16 --float_support=FPv4SPD16 -me -Ooff --include_path="C:/Users/davej/workspace_v9/Final_8Ball_DavidJ" --include_path="C:/TI/CC3200SDK_1.5.0/cc3200-sdk/simplelink/" --include_path="C:/TI/CC3200SDK_1.5.0/cc3200-sdk/simplelink/include" --include_path="C:/TI/CC3200SDK_1.5.0/cc3200-sdk/simplelink/source" --include_path="C:/TI/CC3200SDK_1.5.0/cc3200-sdk/driverlib/" --include_path="C:/TI/CC3200SDK_1.5.0/cc3200-sdk/inc/" --include_path="C:/TI/CC3200SDK_1.5.0/cc3200-sdk/example/common/" --include_path="C:/TI/CC3200SDK_1.5.0/cc3200-sdk/simplelink_extlib/provisioninglib" --include_path="C:/ti/ccs930/ccs/tools/compiler/ti-cgt-arm_18.12.4.LTS/include" --define=ccs --define=cc3200 -g --diag_warning=225 --diag_wrap=off --display_error_number --abi=eabi --preproc_with_compile --preproc_dependency="$(basename $(<F)).d_raw" $(GEN_OPTS__FLAG) "$<"
	@echo 'Finished building: "$<"'
	@echo ' '

network_common.obj: C:/ti/CC3200SDK_1.5.0/cc3200-sdk/example/common/network_common.c $(GEN_OPTS) | $(GEN_FILES) $(GEN_MISC_FILES)
	@echo 'Building file: "$<"'
	@echo 'Invoking: ARM Compiler'
	"C:/ti/ccs930/ccs/tools/compiler/ti-cgt-arm_18.12.4.LTS/bin/armcl" -mv7M4 --code_state=16 --float_support=FPv4SPD16 -me -Ooff --include_path="C:/Users/davej/workspace_v9/Final_8Ball_DavidJ" --include_path="C:/TI/CC3200SDK_1.5.0/cc3200-sdk/simplelink/" --include_path="C:/TI/CC3200SDK_1.5.0/cc3200-sdk/simplelink/include" --include_path="C:/TI/CC3200SDK_1.5.0/cc3200-sdk/simplelink/source" --include_path="C:/TI/CC3200SDK_1.5.0/cc3200-sdk/driverlib/" --include_path="C:/TI/CC3200SDK_1.5.0/cc3200-sdk/inc/" --include_path="C:/TI/CC3200SDK_1.5.0/cc3200-sdk/example/common/" --include_path="C:/TI/CC3200SDK_1.5.0/cc3200-sdk/simplelink_extlib/provisioninglib" --include_path="C:/ti/ccs930/ccs/tools/compiler/ti-cgt-arm_18.12.4.LTS/include" --define=ccs --define=cc3200 -g --diag_warning=225 --diag_wrap=off --display_error_number --abi=eabi --preproc_with_compile --preproc_dependency="$(basename $(<F)).d_raw" $(GEN_OPTS__FLAG) "$<"
	@echo 'Finished building: "$<"'
	@echo ' '

startup_ccs.obj: C:/ti/CC3200SDK_1.5.0/cc3200-sdk/example/common/startup_ccs.c $(GEN_OPTS) | $(GEN_FILES) $(GEN_MISC_FILES)
	@echo 'Building file: "$<"'
	@echo 'Invoking: ARM Compiler'
	"C:/ti/ccs930/ccs/tools/compiler/ti-cgt-arm_18.12.4.LTS/bin/armcl" -mv7M4 --code_state=16 --float_support=FPv4SPD16 -me -Ooff --include_path="C:/Users/davej/workspace_v9/Final_8Ball_DavidJ" --include_path="C:/TI/CC3200SDK_1.5.0/cc3200-sdk/simplelink/" --include_path="C:/TI/CC3200SDK_1.5.0/cc3200-sdk/simplelink/include" --include_path="C:/TI/CC3200SDK_1.5.0/cc3200-sdk/simplelink/source" --include_path="C:/TI/CC3200SDK_1.5.0/cc3200-sdk/driverlib/" --include_path="C:/TI/CC3200SDK_1.5.0/cc3200-sdk/inc/" --include_path="C:/TI/CC3200SDK_1.5.0/cc3200-sdk/example/common/" --include_path="C:/TI/CC3200SDK_1.5.0/cc3200-sdk/simplelink_extlib/provisioninglib" --include_path="C:/ti/ccs930/ccs/tools/compiler/ti-cgt-arm_18.12.4.LTS/include" --define=ccs --define=cc3200 -g --diag_warning=225 --diag_wrap=off --display_error_number --abi=eabi --preproc_with_compile --preproc_dependency="$(basename $(<F)).d_raw" $(GEN_OPTS__FLAG) "$<"
	@echo 'Finished building: "$<"'
	@echo ' '


