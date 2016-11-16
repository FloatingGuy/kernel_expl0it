#include <stdio.h>



char *Vul_devices[3] = {
	"memdev0", "memdev1", "memdev2"
};

int get_kernel_addr(unsigned int *kernel_addr){
	FILE* fp;
	char *buffer, *str;
	fp = fopen("/proc/iomem", "r");
	if (!fp){
		printf("open /proc/iomem failed");
		return false;
	}

	buffer = (char *)malloc(128);
	while (str = fgets(buffer, 128, fp)){
		if （strstr(str, "Kernel text"）|| strstr(str,"Kernel code")
		{
			str = strtok(str, ":");
			str = strtok(str, "-");
			str += 2;
			printf("%s\n",str);
			break;
		}
	}

	sscanf(buffer, "%x", kernel_addr);

}

int poc()
{

	get_device_list();

}

int main(){
	
	poc();
	return 0;
}