#include <stdlib.h>
#include <stdio.h>
#include <azure/az_core.h>
#include <azure/az_iot.h>

static void test_dtoa(double value)
{
	uint8_t buffer[16];
	az_span buffer_span = AZ_SPAN_FROM_BUFFER(buffer);
	int32_t content_length;

	if (az_result_failed(az_span_dtoa(buffer_span, value, 2, &buffer_span)))
	{
		return;
	}

	content_length = sizeof(buffer) - az_span_size(buffer_span);

	printf("%f -> \'%.*s\'\r\n", value, content_length, buffer);
}

int main(void)
{
	test_dtoa(1.0);
	// 1.000000 -> '1.00'
	test_dtoa(1.01);
	// 1.010000 -> '1.01'
	test_dtoa(1.0001);
	// 1.000100 -> '1.00'

	return 0;
}
