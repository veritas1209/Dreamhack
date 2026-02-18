buf[503] = __readfsqword(0x28u);
init();
dummyfunc();
puts("[*] welcome to HAEG!");

for ( i = 0; i <= 9; ++i )
  buf[i] = malloc(0x50uLL);

free(buf[9]);
free(buf[6]);
free(buf[0]);

printf("[+] select chunk to modify(idx) : ");
__isoc99_scanf("%lu", &v5);
if ( v5 > 9 )
{
  puts("[*] NOP!!");
  return 0;
}
else
{
  printf("[+] input data : ");
  if ( read(0, buf[v5], 73uLL) < 0 )
  {
    puts("[*] NOP!!");
    exit(0);
  }
  malloc(80uLL);
  v6 = malloc(80uLL);
  printf("[+] input comment : ");
  if ( read(0, v6, 0x49uLL) < 0 )
  {
    puts("[*] NOP!!");
    exit(0);
  }
  puts("GOOD~~BYE~~");
  return 0;
}