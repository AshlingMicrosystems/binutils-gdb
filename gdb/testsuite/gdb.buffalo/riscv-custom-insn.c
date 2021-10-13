/* For the Buffalo project.  */

#define TEST(LABEL,INSN,RESULT)			\
  do						\
    {						\
      asm (#LABEL ":\t.globl " #LABEL "\n");	\
      asm (INSN ::: "memory");			\
    }						\
  while (0)



void
custom_insn ()
{
  /* Tests are either written using the TEST macro, in which case the
     entire test case must appear on a single line, the exp script
     searches for the TEST directive, and can only handle them being on a
     single line.

     If you absolutely need to write a multi-line asm statement for
     clarity, then use a LABEL/INSN comment, there's an example below,
     however, take care to ensure that the label in the comment matches a
     label in the asm statement.  */

  TEST (L1, ".insn r 0x63, 0x2, 0x5, x3, x4, x5", "add_x gp, tp, t0");
  TEST (L2, ".insn i 0x7b, 0x1, x3, x4, 18", "addi_x gp, tp, 18");
  TEST (L3, ".insn i 0x5b, 0x5, x7, x8, 25", "lw_x t2, 25\(fp\)");
  TEST (L4, ".insn s 0x67, 0x5, x9, 17(x10)", "sw_x s1, 17\(a0\)");
  TEST (L5, ".insn j 0x73, x11, main", "jal_x a1, 0x[0-9a-f]+ <main>");
  TEST (L6, ".insn u 0x5b, x12, 15", "lui_x a2, 15");
  TEST (L7, ".insn cr 0x2, 0x9, x1, x2", "c\.add_x ra, sp");
  TEST (L8, ".insn ci 0x1, 0x0, x3, 14", "c\.addi_x gp, 14");
  TEST (L9, ".insn ciw 0x0, 0x0, x8, 16", "c\.addi4spn_x fp, 256");

  /* LABEL = "L10", INSN = "beq_x a3, a4, 0x[0-9a-f]+ <custom_insn\+[0-9]+>"  */
  asm ("L10:	.globl L10\n"
       ".insn b 0x0f, 0x5, x13, x14, 1f\n"
       "nop\n"
       "nop\n"
       "1:\n"
       "nop" ::: "memory");

  TEST (L11, ".insn css 0x2, 0x6, x4, 15", "c.swsp_x a5, 204");
  TEST (L12, ".insn cl 0x0, 0x6, x9, 6(x11)", "c.lw_x s1, a1 64");
  TEST (L13, ".insn cs 0x1 , 0x4, x9, 5(x10)", "c\.st_x s1, 5\(a0\)");

  /* LABEL = "L14", INSN = "c\.beqz_x s1, 0x[0-9a-f]+ <custom_insn\+[0-9]+>"  */
  asm ("L14:	.globl L10\n"
       ".insn cb 0x1, 0x6, x9, 1f\n"
       "nop\n"
       "nop\n"
       "1:\n"
       "nop" ::: "memory");

  /* LABEL = "L15", INSN = "c\.j_x 0x[0-9a-f]+ <custom_insn\+[0-9]+>"  */
  asm ("L15:	.globl L10\n"
       ".insn cj 0x1, 0x5, 1f\n"
       "nop\n"
       "nop\n"
       "1:\n"
       "nop" ::: "memory");
}

int
main ()
{
  custom_insn ();
  return 0;
}
