; Owned source control for liveness of the return value and state write.
source_filename = "r04-slicing-control"

define i64 @fixture_projection(i64 %a, i64 %b, ptr %state) {
entry:
  %observed = add i64 %a, 7
  %unused = xor i64 %b, 12
  %also_unused = add i64 %unused, 9
  store i64 %observed, ptr %state
  ret i64 %observed
}
